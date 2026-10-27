"""Artifact envelope schema and checks.

A consumer calls `read_artifact` on a download directory. It rejects a missing
file, an extra file or a file over the size cap of its kind, checks the SHA-256
digest of the file bytes before it parses anything, then validates the envelope
against the schema. The publisher then calls `check_context`.
"""

from __future__ import annotations

import hashlib
import hmac
import errno
import json
import os
import re
import stat
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"

# One artifact holds exactly one file.
MAX_FILES = 1
# Byte cap on the envelope file per kind, applied before the digest and before parsing.
MAX_BYTES_BY_KIND = {"bundle": 16 * 1024 * 1024, "pass": 1024 * 1024}

_DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")

# Analyze writes each pass record as `<root>/pass-<name>/pass-<name>.json`, and
# the publisher reads it from there. The names are fixed in trusted code.
PASS_FILE_NAMES = {name: f"pass-{name}.json" for name in ("review", "security", "supply-chain")}


def pass_dir_name(name: str) -> str:
    if name not in PASS_FILE_NAMES:
        raise EnvelopeError(f"unknown pass {name!r}")
    return f"pass-{name}"


class EnvelopeError(Exception):
    """The artifact or envelope is not acceptable. The gate fails closed."""


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _first_error(name: str, doc: Any) -> str | None:
    errors = sorted(_validator(name).iter_errors(doc), key=lambda e: list(e.absolute_path))
    if not errors:
        return None
    e = errors[0]
    where = "/".join(repr(p) for p in e.absolute_path) or "<root>"
    return f"{where}: [{e.validator}] {e.message[:200]}"


def validate_findings(doc: Any) -> None:
    err = _first_error("findings", doc)
    if err:
        raise EnvelopeError(f"findings schema: {err}")


def validate_envelope(doc: Any) -> None:
    """Check the envelope against the schema.

    Payload by kind and status (K-7): a `bundle` with status `ok` or
    `skipped-size` carries the prefilter result, coverage and dependency data
    (a skipped-size bundle omits only the content for Claude). A `pass` record
    with status `ok` carries a payload that must match the findings schema.
    Every other payload is null.

    A `pass` record of any status may carry `meta`: the failure reason, the
    response model and stop reason, the digest of the request schema and the
    token usage. The gate never reads risk from it. A `bundle` with `meta` is
    rejected."""
    err = _first_error("envelope", doc)
    if err:
        raise EnvelopeError(f"envelope schema: {err}")
    if doc["kind"] == "pass" and doc["status"] == "ok":
        validate_findings(doc["payload"])


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_digest(data: bytes, expected: str) -> None:
    """Compare the SHA-256 of `data` with `expected` (`sha256:<hex>` or bare hex)."""
    m = _DIGEST_RE.match(expected or "")
    if not m:
        raise EnvelopeError("digest: malformed expected digest")
    if not hmac.compare_digest(sha256_hex(data), m.group(1).lower()):
        raise EnvelopeError("digest mismatch")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def parse_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EnvelopeError(f"invalid JSON: {exc}") from exc


def read_artifact(
    directory: Path | str,
    *,
    kind: str,
    expected_name: str,
    expected_digest: str,
    max_bytes: int | None = None,
    max_files: int = MAX_FILES,
) -> dict[str, Any]:
    """Read and validate the envelope in one download directory.

    `expected_digest` is the SHA-256 of the file bytes that the producer
    computed in a trusted step. `max_bytes` defaults to the cap for `kind`.
    Order: file count, name, type, size, digest, parse, schema, kind.
    """
    if kind not in MAX_BYTES_BY_KIND:
        raise EnvelopeError(f"unknown kind {kind!r}")
    if max_bytes is None:
        max_bytes = MAX_BYTES_BY_KIND[kind]
    d = Path(directory)
    if not d.is_dir():
        raise EnvelopeError("artifact directory missing")
    entries = list(d.iterdir())
    if len(entries) > max_files:
        raise EnvelopeError(f"extra file: {len(entries)} entries, cap {max_files}")
    if not any(e.name == expected_name for e in entries):
        raise EnvelopeError(f"missing file {expected_name}")
    not_regular = EnvelopeError(f"{expected_name} is not a regular file")
    try:
        fd = os.open(d / expected_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR):
            raise not_regular from exc
        raise EnvelopeError(f"cannot open {expected_name}: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise not_regular
        if st.st_size > max_bytes:
            raise EnvelopeError(f"{expected_name} over size cap {max_bytes}")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise EnvelopeError(f"{expected_name} over size cap {max_bytes}")
    check_digest(data, expected_digest)
    doc = parse_json(data)
    validate_envelope(doc)
    if doc["kind"] != kind:
        raise EnvelopeError(f"kind mismatch: expected {kind}, got {doc['kind']}")
    return doc


SNAPSHOT_FIELDS = ("head_sha", "base_repository_id", "base_ref", "base_tip_sha", "merge_base_sha")


def check_context(
    doc: Mapping[str, Any],
    *,
    repository_id: int,
    pr_number: int,
    run_id: int,
    run_attempt: int,
    snapshot: Mapping[str, Any],
) -> None:
    """Check that a validated envelope matches the trusted run context and the
    bundle snapshot. All expected values come from trusted code, never from an
    artifact. Raise `EnvelopeError` that names every field that differs."""
    expected: dict[str, Any] = {
        "repository_id": repository_id,
        "pr_number": pr_number,
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    for f in SNAPSHOT_FIELDS:
        if f not in snapshot:
            raise EnvelopeError(f"snapshot missing {f}")
        expected[f] = snapshot[f]
    bad = [f for f, v in expected.items() if type(doc.get(f)) is not type(v) or doc.get(f) != v]
    if bad:
        raise EnvelopeError("context mismatch: " + ", ".join(bad))
