"""evals.py: the eval runner. No network: a fake Anthropic client and in-memory
transports."""

import base64
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from oc_review import analyze, collect, evals

UNIT_FIX = Path(__file__).parent / "fixtures" / "analyze"
SMOKE = Path(__file__).resolve().parents[1] / "fixtures" / "eval-smoke"
JOB_SHA = "d" * 40
CONFIGURED = analyze.FederationIds(
    "fdrl_01AbCdEfGhIjKlMnOpQrStUv", "2bc920f9-1111-4222-8333-444455556666", "svac_01AbCdEfGhIjKlMnOpQrStUv"
)


FAKE_EXPECTED = {"gate": "fail", "findings": [{"category": "security", "severity": "high"}]}


def _b64(doc):
    return base64.urlsafe_b64encode(json.dumps(doc).encode()).rstrip(b"=").decode()


GOOD_JWT = (
    f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}."
    f"{_b64({'aud': analyze.OIDC_AUDIENCE, 'job_workflow_sha': JOB_SHA, 'sub': 'repo:OperationCode@1/x'})}.c2ln"
)


class FakeStream:
    def __init__(self, text):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        yield SimpleNamespace(type="stream_event")

    def get_final_message(self):
        usage = SimpleNamespace(input_tokens=100, output_tokens=20, cache_creation_input_tokens=0,
                                cache_read_input_tokens=0, iterations=None)
        return SimpleNamespace(model="claude-opus-5-5", stop_reason="end_turn", usage=usage,
                               content=[SimpleNamespace(type="text", text=self.text)])


class FakeClient:
    def __init__(self, findings=None):
        doc = json.loads((UNIT_FIX / "findings.json").read_text())
        if findings is not None:
            doc = {"summary": doc["summary"], "findings": findings}
        self.text = json.dumps(doc)
        self.calls = 0
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self.stream))

    def stream(self, **kwargs):
        self.calls += 1
        return FakeStream(self.text)


def oidc(url, request_token):
    return 200, json.dumps({"value": GOOD_JWT}).encode()


def factory_for(client, seen=None):
    def factory(token_file, *, deadline, clock, federation):
        if seen is not None:
            seen.append(federation)
        return client

    return factory


def make_case(root, name="case1", expected=None):
    d = root / name
    d.mkdir(parents=True)
    shutil.copy(SMOKE / "bundle.json", d / "bundle.json")
    # the fake client returns a high security finding, so the default case expects it
    expected = FAKE_EXPECTED if expected is None else expected
    (d / "expected.json").write_text(json.dumps(expected))
    return d


def run(tmp_path, client, *, federation=CONFIGURED, seen=None):
    env = {"JOB_WORKFLOW_SHA": JOB_SHA, "RUNNER_TEMP": str(tmp_path / "rt"),
           "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"}
    (tmp_path / "rt").mkdir(exist_ok=True)
    return evals.main(
        ["--fixtures-dir", str(tmp_path / "fixtures"), "--out-dir", str(tmp_path / "out")],
        environ=env, oidc_transport=oidc, client_factory=factory_for(client, seen), federation=federation,
        sleep=lambda s: None,
    )


def result_lines(tmp_path):
    return [json.loads(x) for x in (tmp_path / "out" / "results.jsonl").read_text().splitlines()]


def test_matching_case_exits_zero(tmp_path, capsys):
    make_case(tmp_path / "fixtures")
    client, seen = FakeClient(), []
    assert run(tmp_path, client, seen=seen) == 0
    [r] = result_lines(tmp_path)
    assert r["matched"] and r["mismatches"] == [] and client.calls == 3
    assert seen == [CONFIGURED] * 1
    assert r["usage"]["input_tokens"] == 300 and r["usage"]["output_tokens"] == 60
    assert json.loads(capsys.readouterr().out.splitlines()[0]) == r


def test_mismatch_exits_one(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "pass"})
    assert run(tmp_path, FakeClient()) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and any(m.startswith("gate:") for m in r["mismatches"])


def test_missing_finding_is_a_mismatch(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "fail", "findings": [{"category": "dependency", "severity": "low"}]})
    assert run(tmp_path, FakeClient()) == 1
    assert "missing finding dependency/low" in result_lines(tmp_path)[0]["mismatches"]


def test_hard_block_codes_are_compared(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "fail", "hard_blocks": ["bidi-control"]})
    assert run(tmp_path, FakeClient()) == 1
    assert any(m.startswith("hard blocks:") for m in result_lines(tmp_path)[0]["mismatches"])


def test_zero_cases_exits_one(tmp_path):
    (tmp_path / "fixtures").mkdir()
    assert run(tmp_path, FakeClient()) == 1


def test_missing_fixtures_dir_exits_one(tmp_path):
    assert run(tmp_path, FakeClient()) == 1


def test_placeholders_make_no_call(tmp_path):
    make_case(tmp_path / "fixtures")
    client = FakeClient()
    assert run(tmp_path, client, federation=evals.eval_federation()) == 1
    [r] = result_lines(tmp_path)
    assert client.calls == 0
    assert {p["reason"] for p in r["passes"].values()} == {"federation not configured"}
    assert any("federation not configured" in m for m in r["mismatches"])


def test_module_placeholders_are_eval_placeholders():
    assert analyze.ids_are_placeholders(evals.eval_federation())


def test_failed_pass_is_not_a_match(tmp_path):
    make_case(tmp_path / "fixtures")
    client = FakeClient()
    client.text = "not json"
    assert run(tmp_path, client) == 1
    assert not result_lines(tmp_path)[0]["matched"]


def test_bad_case_fails_and_others_run(tmp_path):
    fx = tmp_path / "fixtures"
    make_case(fx, "a-bad")
    (fx / "a-bad" / "expected.json").write_text("{")
    make_case(fx, "b-good")
    assert run(tmp_path, FakeClient()) == 1
    bad, good = result_lines(tmp_path)
    assert not bad["matched"] and good["matched"]


def test_output_has_no_currency(tmp_path):
    make_case(tmp_path / "fixtures")
    run(tmp_path, FakeClient())
    text = (tmp_path / "out" / "results.jsonl").read_text()
    assert "$" not in text and "usd" not in text.lower() and "cost" not in text.lower()


def test_pr_transport_allows_only_the_one_pr():
    bundle = json.loads((SMOKE / "bundle.json").read_text())
    t = evals.pr_transport(bundle)
    url = f"https://api.github.com/repos/{evals.EVAL_REPOSITORY}/pulls/{bundle['pr_number']}"
    ok = t(collect.HttpRequest("GET", url, {}, 1000, 1.0))
    assert ok.status == 200 and json.loads(ok.body)["head"]["sha"] == bundle["head_sha"]
    for bad in (url + "/files", "https://example.com/x", url.replace("api.github.com", "evil.example")):
        with pytest.raises(AssertionError):
            t(collect.HttpRequest("GET", bad, {}, 1000, 1.0))
    with pytest.raises(AssertionError):
        t(collect.HttpRequest("POST", url, {}, 1000, 1.0))


def test_smoke_fixture_expects_only_what_is_deterministic():
    # the live model decides findings and the gate; only code decides hard blocks
    expected = json.loads((SMOKE / "expected.json").read_text())
    assert set(expected) <= {"hard_blocks"} and expected.get("hard_blocks", []) == []


def test_smoke_fixture_matches_any_valid_output(tmp_path):
    fx = tmp_path / "fixtures"
    d = make_case(fx)
    shutil.copy(SMOKE / "expected.json", d / "expected.json")
    assert run(tmp_path, FakeClient(findings=[])) == 0
    assert result_lines(tmp_path)[0]["matched"]


def test_matching_hard_blocks_pass(tmp_path):
    d = make_case(tmp_path / "fixtures", expected={"hard_blocks": ["bidi-control-characters"]})
    bundle = json.loads((d / "bundle.json").read_text())
    bundle["payload"]["prefilter"]["hard_blocks"] = [{
        "id": "bidi-control-characters", "level": "hard_block", "detail": "bidi control characters",
        "file": "src/a.js", "subject": None, "lines": [3], "count": 1,
    }]
    (d / "bundle.json").write_text(json.dumps(bundle))
    assert run(tmp_path, FakeClient()) == 0
    [r] = result_lines(tmp_path)
    assert r["matched"] and r["gate"] == "fail"


def test_malformed_expected_finding_is_a_mismatch(tmp_path):
    make_case(tmp_path / "fixtures", expected={"findings": [{"category": "security"}, "oops"]})
    assert run(tmp_path, FakeClient()) == 1
    mismatches = result_lines(tmp_path)[0]["mismatches"]
    assert len([m for m in mismatches if m.startswith("bad expected finding")]) == 2


def test_bad_gate_value_is_a_failed_case(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "maybe"})
    assert run(tmp_path, FakeClient()) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and "gate must be pass or fail" in r["mismatches"][0]


@pytest.mark.parametrize("expected", [
    {"finding": [{"category": "security", "severity": "high"}]},
    {"findings": "security"},
    {"hard_blocks": [1]},
    {"gate": "pass", "evil\nkey": 1},
])
def test_invalid_expectation_is_a_failed_case_before_any_call(tmp_path, expected):
    make_case(tmp_path / "fixtures", expected=expected)
    seen = []
    assert run(tmp_path, FakeClient(), seen=seen) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and r["mismatches"][0].startswith("EvalError: expected.json:")
    assert seen == []


def test_results_are_written_per_case(tmp_path, monkeypatch):
    fx = tmp_path / "fixtures"
    make_case(fx, "a-good")
    make_case(fx, "b-good")

    real = evals.run_case
    calls = []

    def crash_on_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt  # not an Exception: main does not catch it
        return real(*args, **kwargs)

    monkeypatch.setattr(evals, "run_case", crash_on_second)
    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, FakeClient())
    assert [r["case"] for r in result_lines(tmp_path)] == ["a-good"]


def test_stdout_is_one_line_per_case_for_a_hostile_case_name(tmp_path, capsys):
    make_case(tmp_path / "fixtures", "a\n::add-mask::x", expected={"gate": "maybe"})
    run(tmp_path, FakeClient())
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1 and not out.startswith("::")
