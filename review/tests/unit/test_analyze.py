"""analyze.py: the Claude call. No network: fake GitHub, OIDC and Anthropic
clients, and the real SDK only over an in-process mock HTTP transport."""

import base64
import json
import re
import stat
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from oc_review import analyze, collect, envelope, render
from oc_review.envelope import sha256_hex

FIX = Path(__file__).parent / "fixtures" / "analyze"
REVIEW_DIR = Path(__file__).resolve().parents[2]
JOB_SHA = "d" * 40
CONFIGURED_IDS = {
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_01AbCdEfGhIjKlMnOpQrStUv",
    "ANTHROPIC_ORGANIZATION_ID": "2bc920f9-1111-4222-8333-444455556666",
    "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_01AbCdEfGhIjKlMnOpQrStUv",
}
PASS_RE = re.compile(r"You are running the (\S+) pass")


def load(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))


def b64url(doc):
    return base64.urlsafe_b64encode(json.dumps(doc).encode()).rstrip(b"=").decode()


def make_jwt(**claims):
    base = {"aud": analyze.OIDC_AUDIENCE, "job_workflow_sha": JOB_SHA, "sub": "repo:OperationCode@10479364/x"}
    return f"{b64url({'alg': 'RS256', 'typ': 'JWT'})}.{b64url({**base, **claims})}.c2lnbmF0dXJl"


GOOD_JWT = make_jwt()


@pytest.fixture
def configured(monkeypatch):
    for name, value in CONFIGURED_IDS.items():
        monkeypatch.setattr(analyze, name, value)


# --- fake Anthropic client --------------------------------------------------


def text_block(text):
    return SimpleNamespace(type="text", text=text)


def message(text=None, *, stop="end_turn", content=None, model="claude-opus-5-5", iterations=None, **usage):
    u = {"input_tokens": 1000, "output_tokens": 200, "cache_creation_input_tokens": 900, "cache_read_input_tokens": 0}
    u.update(usage)
    return SimpleNamespace(
        model=model,
        stop_reason=stop,
        content=content if content is not None else [text_block(text)],
        usage=SimpleNamespace(**u, iterations=iterations),
    )


def findings_text(n=1, **override):
    doc = load("findings")
    f = {**doc["findings"][0], **override}
    return json.dumps({"summary": doc["summary"], "findings": [f] * n})


OK = None  # sentinel: the default good response


@dataclass
class Behavior:
    message: object = OK
    enter_exc: Exception | None = None
    iter_exc: Exception | None = None
    events: int = 2
    block_after_first: threading.Event | None = None


class FakeStream:
    def __init__(self, client, name, behavior):
        self.client, self.name, self.b = client, name, behavior

    def __enter__(self):
        if self.b.enter_exc is not None:
            raise self.b.enter_exc
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        for i in range(self.b.events):
            self.client.record(("event", self.name, i))
            yield SimpleNamespace(type="stream_event")
            if i == 0 and self.b.block_after_first is not None:
                self.b.block_after_first.wait(10)
        if self.b.iter_exc is not None:
            raise self.b.iter_exc

    def get_final_message(self):
        return message(findings_text()) if self.b.message is OK else self.b.message


@dataclass
class FakeClient:
    behaviors: dict = field(default_factory=dict)
    calls: dict = field(default_factory=dict)
    log: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self.stream))

    def record(self, item):
        with self.lock:
            self.log.append(item)

    def stream(self, **kwargs):
        name = PASS_RE.match(kwargs["messages"][-1]["content"]).group(1)
        with self.lock:
            self.calls[name] = kwargs
        self.record(("start", name))
        return FakeStream(self, name, self.behaviors.get(name, Behavior()))


# --- fake GitHub and OIDC transports ------------------------------------------


class FakeGitHub:
    def __init__(self, pr=None, status=200):
        self.pr = load("pr") if pr is None else pr
        self.status = status
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        body = json.dumps(self.pr).encode() if self.status == 200 else b""
        return collect.HttpResponse(self.status, body, request.url)


class FakeOidc:
    def __init__(self, token=GOOD_JWT, status=200, exc=None):
        self.token, self.status, self.exc = token, status, exc
        self.calls = []

    def __call__(self, url, request_token):
        self.calls.append((url, request_token))
        if self.exc is not None:
            raise self.exc
        return self.status, json.dumps({"value": self.token}).encode()


# --- harness -------------------------------------------------------------------


@dataclass
class Run:
    code: int
    records: dict
    raw: dict
    outputs: dict
    client: FakeClient
    github: FakeGitHub
    oidc: FakeOidc
    out_dir: Path
    token_files: list


def run_main(tmp_path, *, client=None, bundle=None, digest=None, github=None, oidc=None, env=None,
             deadline_seconds=analyze.DEADLINE_SECONDS, factory_exc=None, real_factory=None):
    bundle = load("bundle-ok") if bundle is None else bundle
    bundle_dir = tmp_path / "data" / "bundle"
    bundle_dir.mkdir(parents=True)
    data = collect.encode_envelope(bundle)
    (bundle_dir / "bundle.json").write_bytes(data)
    (tmp_path / "event.json").write_text(json.dumps(load("event")))
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    output = tmp_path / "github-output"
    environ = {
        "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
        "GITHUB_TOKEN": "ghs_testtoken",
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_OUTPUT": str(output),
        "RUNNER_TEMP": str(runner_temp),
        "JOB_WORKFLOW_SHA": JOB_SHA,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-request-token",
        **(env or {}),
    }
    environ = {k: v for k, v in environ.items() if v is not None}
    client = client or FakeClient()
    github = github or FakeGitHub()
    oidc = oidc or FakeOidc()
    token_files = []

    def factory(token_file, *, deadline, clock):
        mode = stat.S_IMODE(token_file.stat().st_mode)
        token_files.append((token_file, mode, token_file.read_text()))
        if factory_exc is not None:
            raise factory_exc
        if real_factory is not None:
            return real_factory(token_file, deadline=deadline, clock=clock)
        return client

    out_dir = tmp_path / "data"
    code = analyze.main(
        ["--bundle-dir", str(bundle_dir), "--bundle-digest", digest or sha256_hex(data), "--out-dir", str(out_dir)],
        environ=environ,
        github_transport=github,
        oidc_transport=oidc,
        client_factory=factory,
        deadline_seconds=deadline_seconds,
        sleep=lambda s: None,
    )
    records, raw = {}, {}
    for name in analyze.PASS_NAMES:
        path = out_dir / f"pass-{name}" / f"pass-{name}.json"
        if path.exists():
            raw[name] = path.read_bytes()
            records[name] = json.loads(raw[name])
    outputs = {}
    if output.exists():
        for line in output.read_text().splitlines():
            k, _, v = line.partition("=")
            outputs[k] = v
    return Run(code, records, raw, outputs, client, github, oidc, out_dir, token_files)


def statuses(run):
    return {n: r["status"] for n, r in run.records.items()}


def reasons(run):
    return {n: r["meta"]["reason"] for n, r in run.records.items()}


def assert_three_records(run, bundle=None):
    bundle = load("bundle-ok") if bundle is None else bundle
    assert run.code == 0
    assert list(run.records) == list(analyze.PASS_NAMES)
    for name, doc in run.records.items():
        envelope.validate_envelope(doc)
        assert doc["kind"] == "pass" and doc["pass"] == name
        assert doc["run_id"] == 123456 and doc["run_attempt"] == 1
        assert doc["repository_id"] == 42 and doc["pr_number"] == 7
        for f in envelope.SNAPSHOT_FIELDS:
            assert doc[f] == bundle[f]
        assert run.outputs[f"{name}-digest"] == sha256_hex(run.raw[name])
        assert run.outputs[f"{name}-status"] == doc["status"]
        assert [p.name for p in (run.out_dir / f"pass-{name}").iterdir()] == [f"pass-{name}.json"]
        assert doc["meta"]["request_schema_sha256"] == analyze.schema_digest(analyze.request_schema())
        if doc["status"] != "ok":
            assert doc["payload"] is None


# --- stripped schema -----------------------------------------------------------


def walk_keywords(schema):
    """Every keyword position of a schema (not property names)."""
    if not isinstance(schema, dict):
        return
    for key, value in schema.items():
        yield key
        if key in ("properties", "$defs", "patternProperties"):
            for sub in value.values():
                yield from walk_keywords(sub)
        elif isinstance(value, dict):
            yield from walk_keywords(value)
        elif isinstance(value, list) and key in ("allOf", "anyOf", "oneOf", "prefixItems", "items"):
            for sub in value:
                yield from walk_keywords(sub)


def test_stripped_schema_has_no_unsupported_keyword():
    full = json.loads((envelope.SCHEMA_DIR / "findings.schema.json").read_text())
    stripped = analyze.request_schema()
    assert not set(walk_keywords(stripped)) & analyze.UNSUPPORTED_SCHEMA_KEYWORDS
    assert set(walk_keywords(full)) & analyze.UNSUPPORTED_SCHEMA_KEYWORDS  # the file stays full
    item = stripped["properties"]["findings"]["items"]
    assert item["required"] == full["properties"]["findings"]["items"]["required"]
    assert item["additionalProperties"] is False
    assert item["properties"]["line"] == {"type": "integer"}
    assert item["properties"]["category"] == full["properties"]["findings"]["items"]["properties"]["category"]


def test_strip_keeps_properties_named_like_keywords():
    schema = {
        "type": "object",
        "properties": {
            "maximum": {"type": "integer", "maximum": 5},
            "minLength": {"type": "string", "minLength": 1},
            "items": {"type": "array", "items": {"type": "string", "maxLength": 3}, "maxItems": 2},
        },
        "required": ["maximum", "minLength"],
        "enum": [{"maxLength": 1}],
        "default": {"minimum": 0},
        "$defs": {"uniqueItems": {"anyOf": [{"type": "string", "maxLength": 4}, {"not": {"minimum": 3}}]}},
    }
    out = analyze.strip_schema(schema)
    assert out["properties"]["maximum"] == {"type": "integer"}
    assert out["properties"]["minLength"] == {"type": "string"}
    assert out["properties"]["items"] == {"type": "array", "items": {"type": "string"}}
    assert out["required"] == ["maximum", "minLength"]
    assert out["enum"] == [{"maxLength": 1}]
    assert out["default"] == {"minimum": 0}
    assert out["$defs"]["uniqueItems"] == {"anyOf": [{"type": "string"}, {"not": {}}]}
    assert schema["properties"]["maximum"]["maximum"] == 5  # input unchanged


def test_schema_digest_is_stable():
    a = analyze.schema_digest(analyze.request_schema())
    b = analyze.schema_digest(json.loads(json.dumps(analyze.request_schema())))
    assert a == b and re.fullmatch(r"[0-9a-f]{64}", a)
    assert analyze.schema_digest({"b": 1, "a": 2}) == analyze.schema_digest({"a": 2, "b": 1})


# --- request shape -------------------------------------------------------------


def test_request_kwargs_per_pass(tmp_path, configured):
    run = run_main(tmp_path)
    assert_three_records(run)
    calls = run.client.calls
    assert set(calls) == set(analyze.PASS_NAMES)
    schema = analyze.request_schema()
    systems = {c["system"] for c in calls.values()}
    users = {json.dumps(c["messages"][0]) for c in calls.values()}
    assert len(systems) == 1 and len(users) == 1
    for name, kw in calls.items():
        assert kw["model"] == "claude-opus-5-5"
        assert "<grounding_rules>" in kw["system"]
        user, last = kw["messages"]
        assert user["role"] == "user"
        assert user["content"][0]["cache_control"] == {"type": "ephemeral"}
        assert last["role"] == "system" and last["content"].startswith(f"You are running the {name} pass")
        assert kw["output_config"]["effort"] == {"review": "medium", "security": "medium", "supply-chain": "high"}[name]
        assert kw["output_config"]["format"] == {"type": "json_schema", "schema": schema}
        assert kw["max_tokens"] == analyze.MAX_TOKENS[name] > 0
        assert kw["fallbacks"] == "default"
        assert kw["betas"] == ["server-side-fallback-2026-07-01"]
        assert "tools" not in kw and "tool_choice" not in kw
        assert 0 < kw["timeout"] <= analyze.DEADLINE_SECONDS


def test_default_client_has_two_retries_and_a_timeout(tmp_path, configured, monkeypatch):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.setenv(var, "must-not-be-used")
    token_file = tmp_path / "token"
    token_file.write_text(GOOD_JWT)
    client = analyze.default_client_factory(token_file, deadline=1e12, clock=lambda: 0.0)
    assert client.max_retries == 2
    assert client.timeout == analyze.DEADLINE_SECONDS
    # Explicit federation credentials: no env credential stands in for them.
    assert client.api_key is None and client.auth_token is None


def test_same_nonce_for_all_passes_and_delimiter_safe(tmp_path, configured):
    run = run_main(tmp_path)
    kw = run.client.calls["review"]
    user_text = kw["messages"][0]["content"][0]["text"]
    nonce = re.match(r"<untrusted_pr_([0-9a-f]{16})>\n", user_text).group(1)
    for c in run.client.calls.values():
        assert c["messages"][0]["content"][0]["text"] == user_text
        assert f"untrusted_pr_{nonce}" in c["system"]
        assert f"untrusted_pr_{nonce}" in c["messages"][1]["content"]
    # Only the open and close tags hold the delimiter, despite the forged title.
    assert user_text.count(f"untrusted_pr_{nonce}") == 2
    assert user_text.endswith(f"</untrusted_pr_{nonce}>")


def test_supply_chain_starts_first(tmp_path, configured):
    run = run_main(tmp_path)
    log = run.client.log
    assert log[0] == ("start", "supply-chain")
    first_event = log.index(("event", "supply-chain", 0))
    for name in ("review", "security"):
        assert log.index(("start", name)) > first_event


def test_other_passes_still_start_when_supply_chain_fails_before_streaming(tmp_path, configured):
    client = FakeClient({"supply-chain": Behavior(enter_exc=api_status_error(500))})
    run = run_main(tmp_path, client=client)
    assert statuses(run) == {"review": "ok", "security": "ok", "supply-chain": "failed"}
    assert reasons(run)["supply-chain"] == analyze.R_UNAVAILABLE


# --- response handling ------------------------------------------------------------


@pytest.mark.parametrize("stop", ["max_tokens", "refusal", "pause_turn", "tool_use", None])
def test_stop_reason_other_than_end_turn_fails(tmp_path, configured, stop):
    client = FakeClient({"security": Behavior(message=message(findings_text(), stop=stop))})
    run = run_main(tmp_path, client=client)
    assert statuses(run) == {"review": "ok", "security": "failed", "supply-chain": "ok"}
    meta = run.records["security"]["meta"]
    assert meta["reason"] == f"stop reason {stop or 'missing'}"
    assert meta["stop_reason"] == stop
    assert meta["model"] == "claude-opus-5-5"
    assert meta["usage"]["output_tokens"] == 200


@pytest.mark.parametrize(
    "text, reason",
    [
        ("not json", analyze.R_BAD_JSON),
        ('{"summary": "a", "summary": "b", "findings": []}', analyze.R_BAD_JSON),
        ('{"summary": "a", "findings": [], "x": NaN}', analyze.R_BAD_JSON),
        ("", analyze.R_BAD_JSON),
        (findings_text(title="t" * 121), f"{analyze.R_SCHEMA}: 'findings'/0/'title': [maxLength]"),
        (findings_text(16), f"{analyze.R_SCHEMA}: 'findings': [maxItems]"),
        ('{"summary": "a"}', f"{analyze.R_SCHEMA}: <root>: [required]"),
    ],
)
def test_bad_response_fails_and_is_not_truncated(tmp_path, configured, text, reason):
    client = FakeClient({"review": Behavior(message=message(text))})
    run = run_main(tmp_path, client=client)
    rec = run.records["review"]
    assert rec["status"] == "failed" and rec["payload"] is None
    assert rec["meta"]["reason"] == reason
    assert "t" * 121 not in run.raw["review"].decode()
    assert statuses(run)["security"] == "ok"


def test_no_text_block_fails(tmp_path, configured):
    msg = message(content=[SimpleNamespace(type="thinking", thinking="")])
    run = run_main(tmp_path, client=FakeClient({"review": Behavior(message=msg)}))
    assert reasons(run)["review"] == analyze.R_NO_TEXT


def test_more_findings_than_the_pass_limit_stay_ok(tmp_path, configured):
    run = run_main(tmp_path, client=FakeClient({"review": Behavior(message=message(findings_text(11)))}))
    rec = run.records["review"]
    assert rec["status"] == "ok" and len(rec["payload"]["findings"]) == 11


def test_final_text_block_after_a_fallback_block_is_parsed(tmp_path, configured):
    fallback = SimpleNamespace(type="fallback", **{"from": {"model": "claude-opus-5-5"}}, to={"model": "x"})
    msg = message(
        content=[text_block("{partial"), fallback, text_block(findings_text())],
        model="claude-opus-5-5",
        iterations=[object(), object()],
    )
    run = run_main(tmp_path, client=FakeClient({"supply-chain": Behavior(message=msg)}))
    rec = run.records["supply-chain"]
    assert rec["status"] == "ok"
    assert rec["payload"] == json.loads(findings_text())
    assert rec["meta"]["usage"]["iterations"] == 2


def test_meta_on_ok_record(tmp_path, configured):
    run = run_main(tmp_path)
    meta = run.records["review"]["meta"]
    assert meta == {
        "reason": None,
        "model": "claude-opus-5-5",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_creation_input_tokens": 900,
                  "cache_read_input_tokens": 0},
        "request_schema_sha256": analyze.schema_digest(analyze.request_schema()),
    }


# --- errors ------------------------------------------------------------------------

REQ = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
SPEND_MSG = "You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC."


def error_body(etype, msg):
    return {"type": "error", "error": {"type": etype, "message": msg}}


def api_status_error(status, etype="api_error", msg="boom"):
    body = error_body(etype, msg)
    resp = httpx2.Response(status, request=REQ, json=body)
    cls = {400: anthropic.BadRequestError, 401: anthropic.AuthenticationError,
           403: anthropic.PermissionDeniedError, 429: anthropic.RateLimitError}.get(status, anthropic.InternalServerError)
    if status not in (400, 401, 403, 429) and status < 500:
        cls = anthropic.APIStatusError
    return cls(msg, response=resp, body=body)


@pytest.mark.parametrize(
    "exc, reason",
    [
        (api_status_error(400, "invalid_request_error", SPEND_MSG), analyze.R_SPEND_LIMIT),
        (api_status_error(400, "invalid_request_error", "messages: bad"), analyze.R_REQUEST_REJECTED),
        (api_status_error(400, "api_error", SPEND_MSG), analyze.R_REQUEST_REJECTED),
        (api_status_error(413, "request_too_large", "too big"), analyze.R_REQUEST_REJECTED),
        (api_status_error(401, "authentication_error", "Authentication failed"), analyze.R_AUTH),
        (api_status_error(403, "permission_error", "no"), analyze.R_AUTH),
        (api_status_error(429, "rate_limit_error", "slow down"), analyze.R_UNAVAILABLE),
        (api_status_error(500), analyze.R_UNAVAILABLE),
        (api_status_error(529, "overloaded_error", "overloaded"), analyze.R_UNAVAILABLE),
        (anthropic.APIConnectionError(request=REQ), analyze.R_UNAVAILABLE),
        (anthropic.APITimeoutError(request=REQ), analyze.R_UNAVAILABLE),
        (anthropic.WorkloadIdentityError("denied", status_code=401), analyze.R_AUTH),
        (anthropic.WorkloadIdentityError("down", status_code=503), analyze.R_UNAVAILABLE),
        (anthropic.IdentityTokenFileError("gone"), analyze.R_AUTH),
        (RuntimeError("bug"), analyze.R_INTERNAL),
    ],
)
def test_error_classification(exc, reason):
    assert analyze.classify_error(exc) == reason


def test_spend_limit_fails_one_pass_others_keep_ok(tmp_path, configured):
    client = FakeClient({"security": Behavior(enter_exc=api_status_error(400, "invalid_request_error", SPEND_MSG))})
    run = run_main(tmp_path, client=client)
    assert run.code == 0
    assert statuses(run) == {"review": "ok", "security": "failed", "supply-chain": "ok"}
    assert reasons(run)["security"] == "workspace spend limit reached"


def test_error_during_the_stream_fails_that_pass(tmp_path, configured):
    client = FakeClient({"review": Behavior(iter_exc=api_status_error(529, "overloaded_error", "x"))})
    run = run_main(tmp_path, client=client)
    assert statuses(run) == {"review": "failed", "security": "ok", "supply-chain": "ok"}
    assert reasons(run)["review"] == analyze.R_UNAVAILABLE


def test_deadline_per_pass(tmp_path, configured):
    release = threading.Event()
    client = FakeClient({"supply-chain": Behavior(block_after_first=release)})
    try:
        run = run_main(tmp_path, client=client, deadline_seconds=0.5)
    finally:
        release.set()
    assert statuses(run) == {"review": "ok", "security": "ok", "supply-chain": "failed"}
    assert reasons(run)["supply-chain"] == analyze.R_DEADLINE


def test_deadline_checked_between_stream_events():
    t = iter([0.0, 1.0, 11.0, 12.0, 13.0])
    client = FakeClient()
    req = {"messages": [{}, {"content": "You are running the review pass."}]}
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(client, req, deadline=10.0, clock=lambda: next(t))
    assert exc.value.reason == analyze.R_DEADLINE
    assert client.calls["review"]["timeout"] == 10.0


def test_no_call_after_the_deadline():
    client = FakeClient()
    with pytest.raises(analyze.PassFailure, match="deadline"):
        analyze.call_pass(client, {}, deadline=1.0, clock=lambda: 2.0)
    assert client.calls == {}


def test_exception_in_one_worker_thread(tmp_path, configured):
    client = FakeClient({"review": Behavior(message=SimpleNamespace())})  # no attributes at all
    client.behaviors["security"] = Behavior()
    run = run_main(tmp_path, client=client)
    assert statuses(run)["review"] == "failed"
    assert statuses(run)["security"] == "ok"

    class Boom(FakeClient):
        def stream(self, **kwargs):
            if "security pass" in kwargs["messages"][-1]["content"]:
                raise KeyboardInterrupt  # not an Exception: the worker still leaves a result
            return super().stream(**kwargs)

    run = run_main(tmp_path / "2", client=Boom())
    assert statuses(run) == {"review": "ok", "security": "failed", "supply-chain": "ok"}
    assert reasons(run)["security"] == analyze.R_INTERNAL


# --- the real SDK over a mock HTTP transport -------------------------------------


def sse(events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def ok_stream_body(text, stop="end_turn"):
    return sse([
        {"type": "message_start", "message": {
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 1, "cache_creation_input_tokens": 5,
                      "cache_read_input_tokens": 0}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 50}},
        {"type": "message_stop"},
    ])


def real_client(handler):
    http = httpx2.Client(transport=httpx2.MockTransport(handler))
    return anthropic.Anthropic(api_key="test-key", max_retries=analyze.MAX_RETRIES, http_client=http)


def a_request(name="review"):
    nonce = "0123456789abcdef"
    rendered = render.render_bundle(load("bundle-ok"), nonce=nonce)
    return analyze.build_request(
        name, system_text=render.load_prompt("system", nonce), user_text=rendered.text,
        pass_text=render.load_prompt(name, nonce), schema=analyze.request_schema(),
    )


def test_real_sdk_accepts_the_request_and_parses_the_stream():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=ok_stream_body(findings_text()))

    first = []
    result = analyze.call_pass(real_client(handler), a_request(), deadline=1e12, clock=lambda: 0.0,
                               on_first_event=lambda: first.append(1))
    assert result.status == "ok" and result.payload == json.loads(findings_text())
    assert result.usage == {"input_tokens": 10, "output_tokens": 50, "cache_creation_input_tokens": 5,
                            "cache_read_input_tokens": 0}
    assert first == [1]
    (req,) = seen
    body = json.loads(req.content)
    assert "server-side-fallback-2026-07-01" in req.headers["anthropic-beta"]
    assert body["fallbacks"] == "default" and body["stream"] is True
    assert "tools" not in body and "tool_choice" not in body
    assert [m["role"] for m in body["messages"]] == ["user", "system"]
    assert body["output_config"]["format"]["type"] == "json_schema"


def test_real_sdk_does_not_retry_the_spend_limit_400():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(400, json=error_body("invalid_request_error", SPEND_MSG))

    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(real_client(handler), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert exc.value.reason == analyze.R_SPEND_LIMIT
    assert len(seen) == 1


def test_real_sdk_other_400_is_a_request_failure_without_retry():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(400, json=error_body("invalid_request_error", "messages.1: bad"))

    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(real_client(handler), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert exc.value.reason == analyze.R_REQUEST_REJECTED
    assert len(seen) == 1


def test_real_sdk_5xx_after_two_retries_is_api_unavailable():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx2.Response(500, headers={"retry-after-ms": "1"}, json=error_body("api_error", "x"))

    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(real_client(handler), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert exc.value.reason == analyze.R_UNAVAILABLE
    assert len(seen) == 3


# --- the default client: federation only, and the deadline per attempt ------------

EXCHANGED = "exchanged-access-token"


class Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


class Api:
    """In-process Anthropic API behind the default client's GuardTransport:
    the token exchange and the Messages calls. `messages` gives one response
    (or exception) per Messages attempt; the last one repeats."""

    def __init__(self, messages=None, *, exchange_status=200, clock=None, step=0.0):
        self.messages = messages or [lambda: httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, content=ok_stream_body(findings_text()))]
        self.exchange_status, self.clock, self.step = exchange_status, clock, step
        self.requests = []
        self.attempts = []  # (start time, read timeout) per Messages attempt

    def __call__(self, request):
        self.requests.append(request)
        if request.url.path == "/v1/oauth/token":
            if self.exchange_status != 200:
                return httpx2.Response(self.exchange_status, json=error_body("authentication_error", "denied"))
            return httpx2.Response(200, json={"access_token": EXCHANGED, "token_type": "Bearer", "expires_in": 600})
        assert request.url.path == "/v1/messages"
        now = self.clock() if self.clock else 0.0
        self.attempts.append((now, request.extensions["timeout"]["read"]))
        if self.clock:
            self.clock.now += self.step
        out = self.messages[min(len(self.attempts), len(self.messages)) - 1]()
        if isinstance(out, Exception):
            raise out
        return out

    def messages_requests(self):
        return [r for r in self.requests if r.url.path == "/v1/messages"]


def default_client(tmp_path, api, *, deadline=1e12, clock=lambda: 0.0):
    token_file = tmp_path / "token"
    token_file.write_text(GOOD_JWT)
    return analyze.default_client_factory(token_file, deadline=deadline, clock=clock,
                                          transport=httpx2.MockTransport(api))


@pytest.fixture
def no_retry_sleep(monkeypatch):
    sleeps = []
    monkeypatch.setattr(anthropic._base_client.time, "sleep", sleeps.append)
    return sleeps


def test_default_client_authenticates_by_federation_only(tmp_path, configured, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "static-key-from-env")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "static-token-from-env")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    api = Api()
    result = analyze.call_pass(default_client(tmp_path, api), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert result.status == "ok"
    exchange, msg = api.requests
    assert str(exchange.url) == "https://api.anthropic.com/v1/oauth/token"
    body = json.loads(exchange.content)
    assert body["assertion"] == GOOD_JWT
    assert body["federation_rule_id"] == CONFIGURED_IDS["ANTHROPIC_FEDERATION_RULE_ID"]
    assert body["organization_id"] == CONFIGURED_IDS["ANTHROPIC_ORGANIZATION_ID"]
    assert body["service_account_id"] == CONFIGURED_IDS["ANTHROPIC_SERVICE_ACCOUNT_ID"]
    assert (msg.url.scheme, msg.url.host, msg.url.path) == ("https", "api.anthropic.com", "/v1/messages")
    assert msg.headers["authorization"] == f"Bearer {EXCHANGED}"
    assert "x-api-key" not in msg.headers


@pytest.mark.parametrize("header", ["X-Api-Key: static-key-from-env", "x-api-key: k",
                                    "Authorization: Bearer static-token", "Other: 1\nauthorization: Bearer t"])
def test_custom_credential_header_is_refused(tmp_path, configured, monkeypatch, header):
    """Regression: the SDK reads ANTHROPIC_CUSTOM_HEADERS even with explicit
    credentials, and a credential header there made it skip the exchange."""
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", header)
    api = Api()
    with pytest.raises(analyze.CallRefused) as exc:
        default_client(tmp_path, api)
    assert exc.value.reason == analyze.R_STATIC_CREDENTIAL
    assert api.requests == []


def test_custom_credential_header_gives_three_failed_records(tmp_path, configured, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Api-Key: static-key-from-env")
    api = Api()

    def factory(token_file, **kw):
        return analyze.default_client_factory(token_file, transport=httpx2.MockTransport(api), **kw)

    run = run_main(tmp_path, real_factory=factory)
    assert_three_records(run)
    assert set(reasons(run).values()) == {analyze.R_STATIC_CREDENTIAL}
    assert api.requests == [] and not run.token_files[0][0].exists()


def test_other_custom_headers_still_use_federation(tmp_path, configured, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Trace: 1")
    api = Api()
    analyze.call_pass(default_client(tmp_path, api), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert [r.url.path for r in api.requests] == ["/v1/oauth/token", "/v1/messages"]
    assert api.requests[1].headers["authorization"] == f"Bearer {EXCHANGED}"


def test_denied_exchange_cannot_be_bypassed(tmp_path, configured, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "static-key-from-env")
    api = Api(exchange_status=401)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api), a_request(), deadline=1e12, clock=lambda: 0.0)
    assert exc.value.reason == analyze.R_AUTH
    assert api.messages_requests() == []


@pytest.mark.parametrize(
    "url, headers, reason",
    [
        ("https://evil.example/v1/messages", {}, analyze.R_API_HOST),
        ("http://api.anthropic.com/v1/messages", {}, analyze.R_API_HOST),
        ("https://api.anthropic.com/v1/messages", {"X-Api-Key": "k"}, analyze.R_STATIC_CREDENTIAL),
    ],
)
def test_guard_transport_refuses(url, headers, reason):
    seen = []
    guard = analyze.GuardTransport(httpx2.MockTransport(seen.append), deadline=10.0, clock=lambda: 0.0)
    with pytest.raises(analyze.CallRefused) as exc:
        guard.handle_request(httpx2.Request("POST", url, headers=headers))
    assert exc.value.reason == reason and seen == []


def test_guard_transport_cuts_timeouts_and_refuses_at_the_deadline():
    seen = []

    def handler(request):
        seen.append(request.extensions["timeout"])
        return httpx2.Response(200)

    clock = Clock(4.0)
    guard = analyze.GuardTransport(httpx2.MockTransport(handler), deadline=10.0, clock=clock)
    req = httpx2.Request("POST", "https://api.anthropic.com/v1/oauth/token",
                         extensions={"timeout": {"connect": 30.0, "read": 30.0, "write": 2.0, "pool": None}})
    guard.handle_request(req)
    assert seen == [{"connect": 6.0, "read": 6.0, "write": 2.0, "pool": 6.0}]
    clock.now = 10.0
    with pytest.raises(analyze.CallRefused) as exc:
        guard.handle_request(httpx2.Request("POST", "https://api.anthropic.com/v1/oauth/token"))
    assert exc.value.reason == analyze.R_DEADLINE and len(seen) == 1


def test_token_exchange_gets_at_most_the_time_left(tmp_path, configured):
    api = Api()
    clock = Clock(400.0)
    analyze.call_pass(default_client(tmp_path, api, deadline=420.0, clock=clock), a_request(),
                      deadline=420.0, clock=clock)
    assert api.requests[0].extensions["timeout"]["read"] == 20.0


def status_500(**headers):
    return lambda: httpx2.Response(500, headers=headers, json=error_body("api_error", "x"))


def test_retry_attempts_start_before_the_deadline_with_less_time_each(tmp_path, configured, no_retry_sleep):
    """Regression: the SDK gave each retry the first attempt's timeout and
    started retries after the deadline."""
    clock = Clock()
    api = Api([status_500(**{"retry-after-ms": "1"})], clock=clock, step=3.0)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_UNAVAILABLE
    assert api.attempts == [(0.0, 10.0), (3.0, 7.0), (6.0, 4.0)]
    assert len(no_retry_sleep) == 2


def test_no_retry_starts_at_or_after_the_deadline(tmp_path, configured, no_retry_sleep):
    """The reviewer's case: each 500 takes 11 s against a 10 s deadline."""
    clock = Clock()
    api = Api([status_500()], clock=clock, step=11.0)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_DEADLINE
    assert api.attempts == [(0.0, 10.0)]
    assert no_retry_sleep == []


@pytest.mark.parametrize("headers", [{"retry-after": "60"}, {"retry-after-ms": "9500"}])
def test_no_retry_when_the_wait_passes_the_deadline(tmp_path, configured, no_retry_sleep, headers):
    clock = Clock()
    api = Api([status_500(**headers)], clock=clock, step=1.0)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_UNAVAILABLE
    assert len(api.attempts) == 1 and no_retry_sleep == []


def test_no_retry_after_a_connection_error_near_the_deadline(tmp_path, configured, no_retry_sleep):
    clock = Clock()
    api = Api([lambda: httpx2.ConnectError("down")], clock=clock, step=9.8)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_UNAVAILABLE
    assert len(api.attempts) == 1 and no_retry_sleep == []


def test_connection_errors_retry_while_time_is_left(tmp_path, configured, no_retry_sleep):
    clock = Clock()
    api = Api([lambda: httpx2.ConnectError("down")], clock=clock, step=1.0)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_UNAVAILABLE
    assert [t for t, _ in api.attempts] == [0.0, 1.0, 2.0]


def test_spend_limit_is_not_changed_near_the_deadline(tmp_path, configured):
    clock = Clock()
    spend = lambda: httpx2.Response(400, json=error_body("invalid_request_error", SPEND_MSG))  # noqa: E731
    api = Api([spend], clock=clock, step=9.9)
    with pytest.raises(analyze.PassFailure) as exc:
        analyze.call_pass(default_client(tmp_path, api, deadline=10.0, clock=clock), a_request(),
                          deadline=10.0, clock=clock)
    assert exc.value.reason == analyze.R_SPEND_LIMIT


def test_retry_wait_bound():
    assert analyze.retry_wait(None, 0) == 0.5 and analyze.retry_wait(None, 1) == 1.0
    assert analyze.retry_wait(httpx2.Headers({"retry-after-ms": "250"}), 0) == 0.25
    assert analyze.retry_wait(httpx2.Headers({"retry-after": "7"}), 0) == 7.0
    assert analyze.retry_wait(httpx2.Headers({"retry-after-ms": "0", "retry-after": "7"}), 1) == 1.0
    assert 55 < analyze.retry_wait(httpx2.Headers({"retry-after": email_date(60)}), 0) <= 60
    # The SDK's own backoff constants: the bound must follow the SDK.
    from anthropic import _constants
    assert (analyze.SDK_INITIAL_RETRY_DELAY, analyze.SDK_MAX_RETRY_DELAY) == (
        _constants.INITIAL_RETRY_DELAY, _constants.MAX_RETRY_DELAY)


def email_date(seconds_from_now):
    import email.utils
    import time
    return email.utils.formatdate(time.time() + seconds_from_now, usegmt=True)


# --- three records on every path ---------------------------------------------------


@pytest.mark.parametrize("status", ["skipped-size", "stale", "failed"])
def test_bundle_status_gives_three_records_without_calls(tmp_path, configured, status):
    bundle = load("bundle-ok")
    bundle["status"] = status
    if status == "skipped-size":
        p = bundle["payload"]
        bundle["payload"] = {k: p[k] for k in ("prefilter", "coverage", "dependency_delta", "size")}
    else:
        bundle["payload"] = None
    run = run_main(tmp_path, bundle=bundle)
    assert_three_records(run, bundle)
    assert set(statuses(run).values()) == {status}
    assert set(reasons(run).values()) == {f"bundle status {status}"}
    assert run.client.calls == {} and run.github.requests == [] and run.oidc.calls == []
    for rec in run.records.values():
        assert rec["meta"]["model"] is None and rec["meta"]["usage"] is None


@pytest.mark.parametrize(
    "change, stale_reason",
    [
        ({"head": {"sha": "e" * 40}}, "head_sha_changed"),
        ({"base": {"ref": "release", "repo": {"id": 42, "default_branch": "main"}}}, "base_ref_changed"),
    ],
)
def test_stale_at_the_recheck_makes_no_call(tmp_path, configured, change, stale_reason):
    run = run_main(tmp_path, github=FakeGitHub({**load("pr"), **change}))
    assert_three_records(run)
    assert set(statuses(run).values()) == {"stale"}
    assert set(reasons(run).values()) == {f"stale before the calls: {stale_reason}"}
    assert run.client.calls == {} and run.oidc.calls == []
    (req,) = run.github.requests
    assert req.method == "GET" and req.url == "https://api.github.com/repos/OperationCode/back-end/pulls/7"


def test_base_not_default_branch_still_calls(tmp_path, configured):
    pr = load("pr")
    pr["base"]["repo"]["default_branch"] = "develop"
    run = run_main(tmp_path, github=FakeGitHub(pr))
    assert set(statuses(run).values()) == {"ok"}


@pytest.mark.parametrize("gh", [FakeGitHub(status=404), FakeGitHub(pr={"number": 7})])
def test_pr_read_failure_gives_failed_records(tmp_path, configured, gh):
    run = run_main(tmp_path, github=gh)
    assert_three_records(run)
    assert set(reasons(run).values()) == {analyze.R_PR_READ}
    assert run.client.calls == {}


def test_render_error_gives_failed_records(tmp_path, configured, monkeypatch):
    def boom(*a, **k):
        raise render.RenderError("patch without redaction mark")

    monkeypatch.setattr(analyze.render, "render_bundle", boom)
    run = run_main(tmp_path)
    assert_three_records(run)
    assert set(statuses(run).values()) == {"failed"}
    assert set(reasons(run).values()) == {analyze.R_RENDER}
    assert run.client.calls == {} and run.oidc.calls == []


def test_placeholder_federation_refuses_to_call(tmp_path):
    run = run_main(tmp_path)
    assert_three_records(run)
    assert set(statuses(run).values()) == {"failed"}
    assert set(reasons(run).values()) == {"federation not configured"}
    assert run.client.calls == {} and run.oidc.calls == [] and run.token_files == []


@pytest.mark.parametrize(
    "oidc, env, reason",
    [
        (FakeOidc(make_jwt(job_workflow_sha="f" * 40)), {}, analyze.R_OIDC_MISMATCH),
        (FakeOidc(make_jwt(aud="https://example.com")), {}, analyze.R_OIDC_MISMATCH),
        (FakeOidc(), {"JOB_WORKFLOW_SHA": None}, analyze.R_OIDC_MISMATCH),
        (FakeOidc(), {"JOB_WORKFLOW_SHA": "main"}, analyze.R_OIDC_MISMATCH),
        (FakeOidc(status=403), {}, analyze.R_OIDC_UNAVAILABLE),
        (FakeOidc(status=500), {}, analyze.R_OIDC_UNAVAILABLE),
        (FakeOidc(exc=OSError("down")), {}, analyze.R_OIDC_UNAVAILABLE),
        (FakeOidc(token="not-a-jwt"), {}, analyze.R_OIDC_UNAVAILABLE),
        (FakeOidc(token="a.!!!.c"), {}, analyze.R_OIDC_UNAVAILABLE),
        (FakeOidc(), {"ACTIONS_ID_TOKEN_REQUEST_URL": None}, analyze.R_OIDC_UNAVAILABLE),
    ],
)
def test_oidc_problems_give_failed_records_and_no_call(tmp_path, configured, oidc, env, reason):
    run = run_main(tmp_path, oidc=oidc, env=env)
    assert_three_records(run)
    assert set(reasons(run).values()) == {reason}
    assert run.client.calls == {} and run.token_files == []


def test_oidc_request_url_and_retries(tmp_path, configured):
    oidc = FakeOidc()
    run_main(tmp_path, oidc=oidc)
    (url, token), = oidc.calls
    assert url == ("https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0"
                   "&audience=https%3A%2F%2Fapi.anthropic.com")
    assert token == "oidc-request-token"
    flaky = FakeOidc(status=500)
    with pytest.raises(analyze.OidcError):
        analyze.oidc_minter("https://x.example/t", "t", flaky, sleep=lambda s: None)()
    assert len(flaky.calls) == analyze.OIDC_RETRIES + 1


def test_client_factory_error_gives_failed_records(tmp_path, configured):
    run = run_main(tmp_path, factory_exc=RuntimeError("bad"))
    assert_three_records(run)
    assert set(reasons(run).values()) == {analyze.R_INTERNAL}


def test_token_file_and_no_token_in_output(tmp_path, configured, capsys):
    run = run_main(tmp_path)
    (token_file, mode, content), = run.token_files
    assert mode == 0o600
    assert content == GOOD_JWT
    assert token_file.parent == tmp_path / "runner-temp"
    assert not token_file.exists()  # removed after the calls
    out = capsys.readouterr()
    payload = GOOD_JWT.split(".")[1]
    for text in (out.out, out.err, (tmp_path / "github-output").read_text(), *(r.decode() for r in run.raw.values())):
        assert "eyJ" not in text and payload not in text


# --- untrusted bundle -------------------------------------------------------------


def test_bad_bundle_digest_exits_nonzero_without_records(tmp_path, configured):
    run = run_main(tmp_path, digest="0" * 64)
    assert run.code != 0
    assert run.records == {} and run.outputs == {}
    assert run.client.calls == {} and run.github.requests == [] and run.oidc.calls == []


@pytest.mark.parametrize(
    "field_, value",
    [("run_id", 999), ("run_attempt", 2), ("repository_id", 43), ("pr_number", 8)],
)
def test_context_mismatch_exits_nonzero_without_records(tmp_path, configured, field_, value):
    bundle = load("bundle-ok")
    bundle[field_] = value
    run = run_main(tmp_path, bundle=bundle)
    assert run.code != 0 and run.records == {} and run.client.calls == {}


def test_missing_environment_exits_nonzero(tmp_path, configured):
    run = run_main(tmp_path, env={"GITHUB_RUN_ID": None})
    assert run.code != 0 and run.records == {}


@pytest.mark.parametrize("var", ["GITHUB_TOKEN", "RUNNER_TEMP"])
def test_missing_call_prerequisite_gives_three_failed_records(tmp_path, configured, var):
    """Regression (D2): a trusted bundle always gets three records."""
    run = run_main(tmp_path, env={var: None})
    assert_three_records(run)
    assert set(statuses(run).values()) == {"failed"}
    assert set(reasons(run).values()) == {f"missing environment variable: {var}"}
    assert run.client.calls == {} and run.github.requests == [] and run.oidc.calls == []
    assert run.token_files == []


@pytest.mark.parametrize("status", ["skipped-size", "stale", "failed"])
def test_no_call_bundle_needs_no_call_prerequisite(tmp_path, configured, status):
    bundle = load("bundle-ok")
    bundle["status"] = status
    p = bundle["payload"]
    bundle["payload"] = {k: p[k] for k in ("prefilter", "coverage", "dependency_delta", "size")} \
        if status == "skipped-size" else None
    run = run_main(tmp_path, bundle=bundle, env={"GITHUB_TOKEN": None, "RUNNER_TEMP": None})
    assert_three_records(run, bundle)
    assert set(statuses(run).values()) == {status}


def test_missing_github_output_exits_nonzero_before_any_call(tmp_path, configured):
    run = run_main(tmp_path, env={"GITHUB_OUTPUT": None})
    assert run.code != 0 and run.outputs == {}
    assert run.client.calls == {} and run.github.requests == [] and run.oidc.calls == []


def test_pass_bundle_is_not_a_bundle(tmp_path, configured):
    rec = json.loads((Path(__file__).parent / "fixtures/schema/envelope/good-pass-failed-null-payload.json").read_text())
    rec["run_id"] = 123456
    run = run_main(tmp_path, bundle=rec)
    assert run.code != 0 and run.records == {}


# --- records ---------------------------------------------------------------------


def test_record_that_does_not_validate_becomes_failed():
    bundle = load("bundle-ok")
    bad = analyze.PassResult("ok", {"summary": "x", "findings": [], "extra": 1}, None, "m", "end_turn", None)
    doc = analyze.build_record(bundle, "review", bad, run_id=1, run_attempt=1, schema_sha256="a" * 64)
    out = json.loads(analyze.encode_record(doc))
    assert out["status"] == "failed" and out["payload"] is None
    assert out["meta"]["reason"] == analyze.R_RECORD
    envelope.validate_envelope(out)


def test_long_meta_text_is_clipped():
    bundle = load("bundle-ok")
    r = analyze.PassResult("failed", None, "x" * 500, "m" * 500, "s" * 500, None)
    doc = analyze.build_record(bundle, "review", r, run_id=1, run_attempt=1, schema_sha256=None)
    envelope.validate_envelope(doc)
    assert len(doc["meta"]["reason"]) == 200 and "request_schema_sha256" not in doc["meta"]


# --- federation constants -----------------------------------------------------------


def test_federation_constants_have_the_id_format():
    ids = analyze.federation_ids()
    assert analyze.ids_valid(ids)
    assert analyze.ids_valid(analyze.FederationIds(*CONFIGURED_IDS.values()))
    assert not analyze.ids_are_placeholders(analyze.FederationIds(*CONFIGURED_IDS.values()))
    assert not analyze.ids_valid(analyze.FederationIds("fdrl_x", ids.organization_id, ids.service_account_id))


@pytest.mark.release
def test_release_federation_ids_are_not_placeholders():
    """Phase 3 turns this on for every release (`pytest -m release`)."""
    ids = analyze.federation_ids()
    assert analyze.ids_valid(ids)
    assert not analyze.ids_are_placeholders(ids), "federation IDs are still placeholders"


# --- dependency lock ------------------------------------------------------------------


def test_uv_lock_has_hashes_for_anthropic_and_its_deps():
    lock = tomllib.loads((REVIEW_DIR / "uv.lock").read_text())
    packages = {p["name"]: p for p in lock["package"]}
    assert packages["anthropic"]["version"].startswith("1.")
    for p in lock["package"]:
        if p.get("source", {}).get("registry"):
            dists = p.get("wheels", []) + ([p["sdist"]] if "sdist" in p else [])
            assert dists, p["name"]
            assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", d.get("hash", "")) for d in dists), p["name"]


# --- the federation-ID parameter (the eval runner passes its own IDs) -----------------


def _analyze_direct(tmp_path, factory, **kw):
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    event = collect.EventContext.from_event(load("event"))
    return analyze.analyze(
        load("bundle-ok"), event, github=collect.GitHubClient("ghs_t", FakeGitHub(), sleep=lambda s: None),
        mint_oidc=lambda: GOOD_JWT, job_workflow_sha=JOB_SHA, runner_temp=runner_temp,
        client_factory=factory, **kw,
    )


def test_federation_parameter_reaches_the_client_factory(tmp_path):
    other = analyze.FederationIds(*CONFIGURED_IDS.values())
    seen = []

    def factory(token_file, *, deadline, clock, federation):
        seen.append(federation)
        return FakeClient()

    results = _analyze_direct(tmp_path, factory, federation=other)
    assert seen == [other]  # module constants are still placeholders: only the parameter can pass
    assert {r.status for r in results.values()} == {"ok"}


def test_federation_parameter_placeholders_refuse_to_call(tmp_path):
    placeholder = analyze.FederationIds("fdrl_000000000000000000000000", CONFIGURED_IDS["ANTHROPIC_ORGANIZATION_ID"],
                                        CONFIGURED_IDS["ANTHROPIC_SERVICE_ACCOUNT_ID"])
    results = _analyze_direct(tmp_path, lambda *a, **k: pytest.fail("no client"), federation=placeholder)
    assert {r.reason for r in results.values()} == {analyze.R_FEDERATION_NOT_CONFIGURED}


def test_default_federation_path_does_not_pass_the_parameter(tmp_path, configured):
    calls = []

    def factory(token_file, *, deadline, clock):  # no `federation` kwarg: the default path never passes one
        calls.append(1)
        return FakeClient()

    results = _analyze_direct(tmp_path, factory)
    assert calls == [1] and {r.status for r in results.values()} == {"ok"}


def test_default_client_factory_uses_the_federation_parameter(tmp_path, configured):
    token_file = tmp_path / "tok"
    token_file.write_text(GOOD_JWT)
    other = analyze.FederationIds("fdrl_ZyXwVuTsRqPoNmLkJiHgFeDc", "9bc920f9-1111-4222-8333-444455556666",
                                  "svac_ZyXwVuTsRqPoNmLkJiHgFeDc")
    seen = {}

    def api(request):
        if request.url.path == "/v1/oauth/token":
            seen.update(json.loads(request.content))
            return httpx2.Response(200, json={"access_token": "t", "token_type": "Bearer", "expires_in": 600})
        return httpx2.Response(500)

    client = analyze.default_client_factory(token_file, deadline=1e12, clock=lambda: 0.0,
                                            transport=httpx2.MockTransport(api), federation=other)
    try:
        client.beta.messages.create(model="m", max_tokens=1, messages=[{"role": "user", "content": "x"}])
    except Exception:  # noqa: BLE001 - the Messages call is not the point
        pass
    assert seen["federation_rule_id"] == other.rule_id
