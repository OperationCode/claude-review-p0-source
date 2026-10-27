import json
import os

import pytest

from oc_review import envelope
from oc_review.envelope import (
    MAX_BYTES_BY_KIND,
    EnvelopeError,
    check_context,
    check_digest,
    read_artifact,
    sha256_hex,
)

NAME = "bundle.json"


def write(tmp_path, doc, name=NAME):
    data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    (tmp_path / name).write_bytes(data)
    return data


def read(tmp_path, data, **kw):
    return read_artifact(tmp_path, **{"kind": "bundle", **kw}, expected_name=NAME, expected_digest=sha256_hex(data))


def padded(good_envelope, size):
    """Valid envelope JSON of exactly `size` bytes."""
    payload = good_envelope["payload"]
    base = json.dumps({**good_envelope, "payload": {**payload, "p": ""}}).encode()
    pad = size - len(base)
    assert pad >= 0
    data = json.dumps({**good_envelope, "payload": {**payload, "p": "x" * pad}}).encode()
    assert len(data) == size
    return data


def test_reads_valid_artifact(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    assert read(tmp_path, data) == good_envelope


def test_digest_accepts_prefix_and_case(tmp_path):
    d = b"abc"
    check_digest(d, sha256_hex(d))
    check_digest(d, "sha256:" + sha256_hex(d).upper())


def test_digest_mismatch(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    with pytest.raises(EnvelopeError, match="digest mismatch"):
        read_artifact(tmp_path, kind="bundle", expected_name=NAME, expected_digest=sha256_hex(data + b" "))


@pytest.mark.parametrize("bad", ["", "sha256:abc", "md5:" + "0" * 32, "z" * 64])
def test_digest_malformed(bad):
    with pytest.raises(EnvelopeError, match="malformed"):
        check_digest(b"x", bad)


def test_digest_checked_before_parse(tmp_path):
    data = write(tmp_path, b"not json")
    with pytest.raises(EnvelopeError, match="digest mismatch"):
        read_artifact(tmp_path, kind="bundle", expected_name=NAME, expected_digest="0" * 64)
    with pytest.raises(EnvelopeError, match="invalid JSON"):
        read(tmp_path, data)


def test_file_count_at_limit_passes_and_over_fails(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    assert envelope.MAX_FILES == 1
    read(tmp_path, data)  # at limit
    (tmp_path / "extra.json").write_text("{}")  # limit + 1
    with pytest.raises(EnvelopeError, match="extra file"):
        read(tmp_path, data)


def test_extra_directory_counts(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    (tmp_path / "sub").mkdir()
    with pytest.raises(EnvelopeError, match="extra file"):
        read(tmp_path, data)


def test_missing_file(tmp_path):
    with pytest.raises(EnvelopeError, match="missing file"):
        read_artifact(tmp_path, kind="bundle", expected_name=NAME, expected_digest="0" * 64)


def test_wrong_name_single_file(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope, name="other.json")
    with pytest.raises(EnvelopeError, match="missing file"):
        read(tmp_path, data)


def test_missing_directory(tmp_path):
    with pytest.raises(EnvelopeError, match="directory missing"):
        read_artifact(tmp_path / "nope", kind="bundle", expected_name=NAME, expected_digest="0" * 64)


def test_symlink_rejected(tmp_path, good_envelope):
    target = tmp_path / "elsewhere"
    target.mkdir()
    data = write(target, good_envelope, name="real.json")
    d = tmp_path / "dl"
    d.mkdir()
    (d / NAME).symlink_to(target / "real.json")
    with pytest.raises(EnvelopeError, match="not a regular file"):
        read(d, data)


def test_size_cap_at_limit_passes_and_over_fails(tmp_path, good_envelope):
    cap = 2048
    data = padded(good_envelope, cap)  # at limit
    write(tmp_path, data)
    assert read(tmp_path, data, max_bytes=cap)["kind"] == "bundle"
    data = padded(good_envelope, cap + 1)  # limit + 1
    write(tmp_path, data)
    with pytest.raises(EnvelopeError, match="over size cap"):
        read(tmp_path, data, max_bytes=cap)


def test_default_size_caps_per_kind():
    assert MAX_BYTES_BY_KIND == {"bundle": 16 * 1024 * 1024, "pass": 1024 * 1024}


def test_pass_cap_applies_by_default(tmp_path, good_envelope):
    cap = MAX_BYTES_BY_KIND["pass"]
    env = {**good_envelope, "kind": "pass", "pass": "review", "status": "failed", "payload": None}
    env["head_sha"] = "a" * 40
    base = len(json.dumps(env).encode())
    # a pass file one byte over the cap fails, although the bundle cap would allow it
    data = json.dumps({**env, "base_ref": "x" * (cap + 1 - base + len("main"))}).encode()
    assert len(data) == cap + 1
    write(tmp_path, data)
    with pytest.raises(EnvelopeError, match="over size cap"):
        read(tmp_path, data, kind="pass")


def test_unknown_kind(tmp_path):
    with pytest.raises(EnvelopeError, match="unknown kind"):
        read_artifact(tmp_path, kind="x", expected_name=NAME, expected_digest="0" * 64)


def test_kind_mismatch(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    with pytest.raises(EnvelopeError, match="kind mismatch"):
        read(tmp_path, data, kind="pass")


def test_fifo_rejected_without_blocking(tmp_path):
    os.mkfifo(tmp_path / NAME)
    with pytest.raises(EnvelopeError, match="not a regular file"):
        read_artifact(tmp_path, kind="bundle", expected_name=NAME, expected_digest="0" * 64)


def test_open_uses_nofollow(tmp_path, good_envelope, monkeypatch):
    """A symlink swapped in after the listing is refused by the open itself."""
    data = write(tmp_path / "..", good_envelope, name="real.json")
    flags = []
    real_open = os.open

    def spy(path, fl, *a, **k):
        flags.append(fl)
        return real_open(path, fl, *a, **k)

    monkeypatch.setattr(envelope.os, "open", spy)
    d = tmp_path / "dl"
    d.mkdir()
    (d / NAME).write_bytes(data)
    read(d, data)
    assert flags and flags[0] & os.O_NOFOLLOW


SNAP = {
    "head_sha": "a" * 40,
    "base_repository_id": 42,
    "base_ref": "main",
    "base_tip_sha": "b" * 40,
    "merge_base_sha": "c" * 40,
}
CTX = {"repository_id": 42, "pr_number": 7, "run_id": 123456, "run_attempt": 1}


def test_context_match(good_envelope):
    check_context(good_envelope, **CTX, snapshot=SNAP)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository_id", 43),
        ("pr_number", 8),
        ("run_id", 123457),
        ("run_attempt", 2),
        ("head_sha", "d" * 40),
        ("base_repository_id", 43),
        ("base_ref", "dev"),
        ("base_tip_sha", "d" * 40),
        ("merge_base_sha", "d" * 40),
    ],
)
def test_context_mismatch(good_envelope, field, value):
    with pytest.raises(EnvelopeError, match=f"context mismatch: {field}$"):
        check_context({**good_envelope, field: value}, **CTX, snapshot=SNAP)


def test_context_mismatch_lists_all(good_envelope):
    doc = {**good_envelope, "pr_number": 9, "run_id": 1}
    with pytest.raises(EnvelopeError, match="pr_number, run_id"):
        check_context(doc, **CTX, snapshot=SNAP)


def test_context_rejects_bool_for_int(good_envelope):
    with pytest.raises(EnvelopeError, match="run_attempt"):
        check_context({**good_envelope, "run_attempt": True}, **{**CTX}, snapshot=SNAP)


def test_context_snapshot_missing_field(good_envelope):
    snap = {k: v for k, v in SNAP.items() if k != "base_ref"}
    with pytest.raises(EnvelopeError, match="snapshot missing base_ref"):
        check_context(good_envelope, **CTX, snapshot=snap)


def test_size_cap_checked_before_digest(tmp_path):
    write(tmp_path, b"x" * 11)
    with pytest.raises(EnvelopeError, match="over size cap"):
        read_artifact(tmp_path, kind="bundle", expected_name=NAME, expected_digest="0" * 64, max_bytes=10)


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe", b'{"a": 1, "a": 2}', b'{"a": NaN}', b"[1, 2", b""],
)
def test_invalid_json_rejected(tmp_path, raw):
    write(tmp_path, raw)
    with pytest.raises(EnvelopeError, match="invalid JSON"):
        read(tmp_path, raw)


def test_schema_failure_after_digest(tmp_path, good_envelope):
    bad = {**good_envelope, "extra": 1}
    data = write(tmp_path, bad)
    with pytest.raises(EnvelopeError, match="envelope schema"):
        read(tmp_path, data)


def test_schema_error_path_keys_are_quoted(good_envelope):
    bad = {**good_envelope, "payload": {"a\n::error::x": 1}}
    with pytest.raises(EnvelopeError) as ei:
        envelope.validate_envelope(bad)
    assert "\n" not in str(ei.value)


def test_pass_ok_payload_must_match_findings(tmp_path, good_envelope):
    bad = {**good_envelope, "kind": "pass", "pass": "review", "payload": {"summary": "x"}}
    data = write(tmp_path, bad)
    with pytest.raises(EnvelopeError, match="findings schema"):
        read(tmp_path, data, kind="pass")


BUNDLE_PAYLOAD = {"prefilter": {"signals": [], "hard_blocks": []}, "coverage": {}, "dependency_delta": {}}
FINDINGS_PAYLOAD = {"summary": "", "findings": []}


@pytest.mark.parametrize(
    "kind,status,payload",
    [
        ("bundle", "ok", BUNDLE_PAYLOAD),
        # K-7: the size gate skips only the Claude calls; the deterministic results stay.
        ("bundle", "skipped-size", BUNDLE_PAYLOAD),
        ("bundle", "failed", None),
        ("bundle", "stale", None),
        ("pass", "ok", FINDINGS_PAYLOAD),
        ("pass", "skipped-size", None),
        ("pass", "failed", None),
        ("pass", "stale", None),
    ],
)
def test_payload_by_kind_and_status(good_envelope, kind, status, payload):
    doc = {**good_envelope, "kind": kind, "status": status, "payload": payload}
    if kind == "pass":
        doc["pass"] = "review"
    envelope.validate_envelope(doc)
    # A payload where null belongs, or null where a payload belongs, is rejected.
    swapped = None if payload is not None else (BUNDLE_PAYLOAD if kind == "bundle" else FINDINGS_PAYLOAD)
    with pytest.raises(EnvelopeError, match="payload"):
        envelope.validate_envelope({**doc, "payload": swapped})


def test_skipped_size_bundle_payload_needs_the_deterministic_results(good_envelope):
    for key in BUNDLE_PAYLOAD:
        payload = {k: v for k, v in BUNDLE_PAYLOAD.items() if k != key}
        doc = {**good_envelope, "status": "skipped-size", "payload": payload}
        with pytest.raises(EnvelopeError, match=f"'payload': \\[required\\] '{key}'"):
            envelope.validate_envelope(doc)


@pytest.mark.parametrize("key", ["files", "pr", "content", "anything"])
def test_skipped_size_bundle_has_no_content_for_claude(good_envelope, key):
    # The size gate skipped the Claude calls, so the payload holds only the
    # deterministic results (K-7). Content for Claude is rejected.
    doc = {**good_envelope, "status": "skipped-size", "payload": {**BUNDLE_PAYLOAD, key: []}}
    with pytest.raises(EnvelopeError, match=f"'payload': \\[enum\\] '{key}'"):
        envelope.validate_envelope(doc)
    ok = {**good_envelope, "status": "ok", "payload": {**BUNDLE_PAYLOAD, key: []}}
    envelope.validate_envelope(ok)


def test_skipped_size_bundle_may_carry_size(good_envelope):
    doc = {**good_envelope, "status": "skipped-size", "payload": {**BUNDLE_PAYLOAD, "size": {"estimated_tokens": 1}}}
    envelope.validate_envelope(doc)


def test_pass_file_names():
    assert envelope.PASS_FILE_NAMES == {
        "review": "pass-review.json",
        "security": "pass-security.json",
        "supply-chain": "pass-supply-chain.json",
    }
    assert [envelope.pass_dir_name(n) for n in envelope.PASS_FILE_NAMES] == [
        "pass-review",
        "pass-security",
        "pass-supply-chain",
    ]


@pytest.mark.parametrize("bad", ["", "bundle", "../review", "pass-review"])
def test_pass_dir_name_rejects_unknown(bad):
    with pytest.raises(EnvelopeError, match="unknown pass"):
        envelope.pass_dir_name(bad)


def test_pass_meta_is_optional_and_kind_pass_only(good_envelope):
    from .conftest import load_fixture

    rec = load_fixture("envelope", "good-pass-failed-null-payload")
    envelope.validate_envelope(rec)
    envelope.validate_envelope({**rec, "meta": {"reason": "workspace spend limit reached"}})
    with pytest.raises(EnvelopeError, match=r"<root>: \[not\]"):
        envelope.validate_envelope({**good_envelope, "meta": {}})
