"""Unit tests for the publisher (gate job). No network: a recording fake
transport stands in for api.github.com."""

from __future__ import annotations

import io
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import pytest

from oc_review import collect, envelope, linediff, publish, verdict
from oc_review.collect import HttpRequest, HttpResponse
from oc_review.publish import GitHubApi, PublishContext

REPO = "OperationCode/back-end"
API = f"/repos/{REPO}"
REPO_ID = 42
PR = 7
RUN_ID = 1000
ATTEMPT = 1
HEAD = "a" * 40
TIP = "b" * 40
MB = "c" * 40
OTHER = "d" * 40
AUTHOR = "contributor"
MAINT = "maintainer"
MAINT2 = "admin-user"
BOT = verdict.BOT_LOGIN
T0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)
WORKFLOW = f"OperationCode/.github/{verdict.WORKFLOW_PATH}@{'e' * 40}"
ZWSP = "​"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

BASE_LINES = [f"line {i}" for i in range(1, 31)]
HEAD_LINES = list(BASE_LINES)
HEAD_LINES[9] = "    subprocess.run(cmd, shell=True)"
BASE_TEXT = "\n".join(BASE_LINES) + "\n"
HEAD_TEXT = "\n".join(HEAD_LINES) + "\n"


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- fake GitHub


def _page(items: list, query: dict, url: str) -> tuple[list, dict]:
    per = int(query.get("per_page", 30))
    page = int(query.get("page", 1))
    chunk = items[(page - 1) * per : page * per]
    headers = {}
    if page * per < len(items):
        q = dict(query, page=str(page + 1))
        parts = urllib.parse.urlsplit(url)
        nxt = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))
        headers["link"] = f'<{nxt}>; rel="next"'
    return chunk, headers


ALLOWED_WRITES = (
    ("POST", re.compile(rf"{API}/pulls/{PR}/reviews")),
    ("POST", re.compile(rf"{API}/issues/{PR}/comments")),
    ("PATCH", re.compile(rf"{API}/issues/comments/\d+")),
)


@dataclass
class FakeGitHub:
    """api.github.com for one PR. State is mutable so a hook can change it
    between requests (for example a push during the run)."""

    head: str = HEAD
    base_ref: str = "main"
    default_branch: str = "main"
    tip: str = TIP
    merge_base: str = MB
    issue_comments: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    review_comments: list = field(default_factory=list)
    permissions: dict = field(default_factory=lambda: {MAINT: "write", MAINT2: "admin", AUTHOR: "write"})
    runs: list = field(default_factory=lambda: [{"id": RUN_ID, "path": WORKFLOW}])
    runs_per_page: int | None = None
    runs_total: int | None = None
    review_status: int = 200
    fail: set = field(default_factory=set)  # (method, path, page) -> HTTP 500
    after: Callable[[FakeGitHub, HttpRequest], None] | None = None
    requests: list = field(default_factory=list)
    next_id: int = 5000

    # --- helpers for tests
    @property
    def writes(self) -> list[HttpRequest]:
        return [r for r in self.requests if r.method != "GET"]

    def paths(self, method: str = "GET") -> list[str]:
        return [urllib.parse.urlsplit(r.url).path for r in self.requests if r.method == method]

    def bodies(self, method: str, suffix: str) -> list[dict]:
        return [
            json.loads(r.body)
            for r in self.requests
            if r.method == method and urllib.parse.urlsplit(r.url).path.endswith(suffix)
        ]

    def summary_bodies(self) -> list[str]:
        out = []
        for r in self.writes:
            path = urllib.parse.urlsplit(r.url).path
            if path.endswith(f"/issues/{PR}/comments") or "/issues/comments/" in path:
                out.append(json.loads(r.body)["body"])
        return out

    # --- transport
    def __call__(self, req: HttpRequest) -> HttpResponse:
        self.requests.append(req)
        parts = urllib.parse.urlsplit(req.url)
        assert parts.scheme == "https" and parts.hostname == "api.github.com"
        query = dict(urllib.parse.parse_qsl(parts.query))
        path = parts.path
        if req.method != "GET":
            # Write allowlist: every non-GET request in every test.
            assert any(req.method == m and rx.fullmatch(path) for m, rx in ALLOWED_WRITES), (req.method, path)
            body = json.loads(req.body)
            if path.endswith("/reviews"):
                assert body["event"] == "COMMENT"
        try:
            if (req.method, path, query.get("page", "1")) in self.fail:
                return HttpResponse(500, b"", req.url)
            return self._route(req, path, query)
        finally:
            if self.after is not None:
                self.after(self, req)

    def _json(self, req: HttpRequest, doc: Any, status: int = 200, headers: dict | None = None) -> HttpResponse:
        return HttpResponse(status, json.dumps(doc).encode(), req.url, headers or {})

    def _route(self, req: HttpRequest, path: str, query: dict) -> HttpResponse:
        m = req.method
        if m == "GET" and path == f"{API}/pulls/{PR}":
            return self._json(req, self.pr_doc())
        if m == "GET" and path == f"{API}/git/ref/heads/{self.base_ref}":
            return self._json(req, {"ref": f"refs/heads/{self.base_ref}", "object": {"type": "commit", "sha": self.tip}})
        if m == "GET" and path.startswith(f"{API}/compare/"):
            base, head = path.rsplit("/", 1)[1].split("...")
            assert base == self.tip
            return self._json(req, {"base_commit": {"sha": base}, "merge_base_commit": {"sha": self.merge_base}})
        for suffix, items in (
            (f"/issues/{PR}/comments", self.issue_comments),
            (f"/issues/{PR}/timeline", self.timeline),
            (f"/pulls/{PR}/comments", self.review_comments),
        ):
            if m == "GET" and path == API + suffix:
                chunk, headers = _page(items, query, req.url)
                return self._json(req, chunk, headers=headers)
        if m == "GET" and path.startswith(f"{API}/collaborators/"):
            login = urllib.parse.unquote(path.split("/")[-2])
            if login not in self.permissions:
                return HttpResponse(404, b"", req.url)
            return self._json(req, {"permission": self.permissions[login], "role_name": "x"})
        if m == "GET" and path == f"{API}/actions/runs":
            assert query.get("head_sha") in (HEAD, OTHER)
            per = self.runs_per_page or int(query.get("per_page", 30))
            chunk, headers = _page(self.runs, dict(query, per_page=str(per)), req.url)
            total = self.runs_total if self.runs_total is not None else len(self.runs)
            return self._json(req, {"total_count": total, "workflow_runs": chunk}, headers=headers)
        if m == "POST" and path == f"{API}/pulls/{PR}/reviews":
            if self.review_status != 200:
                return HttpResponse(self.review_status, b"", req.url)
            body = json.loads(req.body)
            for c in body["comments"]:
                self.review_comments.append({"user": {"login": BOT}, "body": c["body"]})
            return self._json(req, {"id": 1})
        if m == "POST" and path == f"{API}/issues/{PR}/comments":
            self.next_id += 1
            body = json.loads(req.body)["body"]
            self.issue_comments.append(api_comment(self.next_id, BOT, body, type="Bot"))
            return self._json(req, {"id": self.next_id}, 201)
        if m == "PATCH" and path.startswith(f"{API}/issues/comments/"):
            cid = int(path.rsplit("/", 1)[1])
            for c in self.issue_comments:
                if c["id"] == cid:
                    c["body"] = json.loads(req.body)["body"]
            return self._json(req, {"id": cid})
        return HttpResponse(404, b"", req.url)

    def pr_doc(self) -> dict:
        return {
            "number": PR,
            "head": {"sha": self.head},
            "base": {
                "ref": self.base_ref,
                "repo": {"id": REPO_ID, "full_name": REPO, "default_branch": self.default_branch},
            },
        }


def api_comment(cid, login, body, created=None, updated=None, type="User"):
    created = created or T0 + timedelta(hours=1)
    return {
        "id": cid,
        "user": {"login": login, "type": type},
        "body": body,
        "created_at": iso(created),
        "updated_at": iso(updated or created),
        "html_url": f"https://github.com/{REPO}/pull/{PR}#issuecomment-{cid}",
    }


def override(cid=1, login=MAINT, reason="false positive, checked by hand", head=HEAD, mb=MB, **kw):
    return api_comment(cid, login, f"/oc-review override {head} {mb} {reason}", **kw)


# ---------------------------------------------------------------- artifacts


def finding(category="bug", severity="low", file="src/app.py", side="head", line=10,
            quote="shell=True", title="t", explanation="e", confidence="high"):
    return {
        "category": category, "severity": severity, "confidence": confidence, "file": file,
        "side": side, "line": line, "quote": quote, "title": title, "explanation": explanation,
    }


BLOCKING = finding("malicious", "high", title="Runs a shell", explanation="shell=True with input")


def env_doc(kind, status="ok", payload=None, pass_name=None, **over):
    doc = {
        "schema_version": 1, "kind": kind, "run_id": RUN_ID, "run_attempt": ATTEMPT,
        "repository_id": REPO_ID, "pr_number": PR, "head_sha": HEAD, "base_repository_id": REPO_ID,
        "base_ref": "main", "base_tip_sha": TIP, "merge_base_sha": MB, "status": status, "payload": payload,
    }
    if pass_name is not None:
        doc["pass"] = pass_name
    doc.update(over)
    return doc


def bundle_doc(status="ok", hard_blocks=(), signals=(), files=None, title="Fix login", body="Small fix.",
               delta=None, **over):
    if status not in ("ok", "skipped-size"):
        return env_doc("bundle", status, None, **over)
    payload = {
        "prefilter": {"signals": list(signals), "hard_blocks": list(hard_blocks)},
        "coverage": {"complete": True, "trees_complete": True, "files_in_comparison": 1, "files_collected": 1,
                     "files": [{"path": "src/app.py", "coverage": "full", "reason": None}]},
        "dependency_delta": delta or {"changes": [], "new_global_sources": [], "failures": []},
    }
    if status == "ok":
        payload["pr"] = {"number": PR, "title": title, "body": body}
        payload["files"] = files if files is not None else [
            {"path": "src/app.py", "old_path": None, "status": "modified",
             "base_content": BASE_TEXT, "head_content": HEAD_TEXT}
        ]
    return env_doc("bundle", status, payload, **over)


USAGE = {"input_tokens": 12000, "output_tokens": 900, "cache_creation_input_tokens": 11000,
         "cache_read_input_tokens": 0, "iterations": 1}


def pass_doc(name, status="ok", findings=(), summary="Looked at the change.", meta=None, **over):
    payload = {"summary": summary, "findings": list(findings)} if status == "ok" else None
    doc = env_doc("pass", status, payload, pass_name=name, **over)
    doc["meta"] = meta if meta is not None else {
        "reason": None, "model": "claude-opus-5-5", "stop_reason": "end_turn" if status == "ok" else None,
        "request_schema_sha256": "f" * 64, "usage": dict(USAGE),
    }
    return doc


def clean_passes(**findings_by_pass):
    return {n: pass_doc(n, findings=findings_by_pass.get(n.replace("-", "_"), ())) for n in verdict.PASS_NAMES}


def write_data(root: Path, bundle: dict | None, passes: dict[str, dict | None]) -> dict[str, str]:
    """Write each artifact in its fixed directory; return the digests (env values)."""
    digests: dict[str, str] = {}
    items = [("bundle", "bundle", collect.BUNDLE_FILE_NAME, bundle)]
    items += [(n, envelope.pass_dir_name(n), envelope.PASS_FILE_NAMES[n], passes.get(n)) for n in verdict.PASS_NAMES]
    for key, dirname, fname, doc in items:
        if doc is None:
            digests[key] = ""
            continue
        d = root / dirname
        d.mkdir(parents=True)
        data = collect.encode_envelope(doc)
        (d / fname).write_bytes(data)
        digests[key] = envelope.sha256_hex(data)
    return digests


def needs_ok(outcome="success"):
    return {
        "collect": {"result": "success", "outputs": {}},
        "analyze": {"result": "success", "outputs": {}},
        "dependency-review": {"result": "success", "outputs": {"outcome": outcome}},
    }


CTX = PublishContext(REPO, REPO_ID, PR, HEAD, AUTHOR, RUN_ID, ATTEMPT)


@dataclass
class Run:
    code: int
    gh: FakeGitHub
    step: str

    @property
    def summary(self) -> str:
        bodies = self.gh.summary_bodies()
        assert bodies, "no summary was written"
        return bodies[-1]

    @property
    def record(self) -> dict:
        m = re.search(r"```\n(\{.*?\})\n```", self.step)
        assert m, self.step
        return json.loads(m.group(1))


def run(tmp_path, gh=None, *, bundle="default", passes=None, needs=None, outcome_env=None, digests=None):
    gh = gh or FakeGitHub()
    bundle = bundle_doc() if bundle == "default" else bundle
    passes = clean_passes() if passes is None else passes
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    real = write_data(data, bundle, passes)
    step = tmp_path / "step-summary.md"
    code = publish.publish(
        GitHubApi("token", gh, sleep=lambda s: None),
        CTX,
        data_dir=data,
        needs=needs_ok() if needs is None else needs,
        dependency_outcome_env=outcome_env,
        digests=real if digests is None else {**real, **digests},
        step_summary=step,
    )
    return Run(code, gh, step.read_text(encoding="utf-8") if step.exists() else "")


def plain(text: str) -> str:
    """What a reader sees: no escaping backslashes, no zero-width breaks."""
    return re.sub(r"\\(.)", r"\1", text, flags=re.S).replace(ZWSP, "")


def reason_codes(text: str) -> set[str]:
    return set(re.findall(r"^- ([a-z-]+) \((?:not waivable|waivable by override)\)", text, re.M))


# ---------------------------------------------------------------- happy path


def test_clean_run_passes_and_posts_summary(tmp_path):
    r = run(tmp_path)
    assert r.code == 0
    assert r.gh.paths("POST") == [f"{API}/issues/{PR}/comments"]
    assert not r.gh.bodies("POST", "/reviews")
    s = r.summary
    assert s.startswith(verdict.STICKY_MARKER)
    assert "## OC Claude review: pass" in s
    assert r.record["result"] == "pass"


def test_summary_has_every_required_field(tmp_path):
    passes = clean_passes(security=[finding("security", "high", title="Shell call")])
    gh = FakeGitHub(issue_comments=[override(1)])
    r = run(tmp_path, gh, passes=passes, bundle=bundle_doc(signals=[
        {"id": "workflow-change", "level": "signal", "detail": "changes a workflow", "file": ".github/workflows/x.yml",
         "subject": None, "lines": [], "count": 1}]))
    s = r.summary
    assert r.code == 0  # waived by the override
    for text in (
        verdict.STICKY_MARKER,
        f"Result for run [{RUN_ID}]",
        f"attempt {ATTEMPT}",
        f"head SHA `{HEAD}`",
        f"merge base `{MB}`",
        "base ref main",
        "### Reasons",
        "blocking-finding (waivable by override)",
        "Override applied: yes. Waived reasons: blocking-finding.",
        f"by {MAINT}",
        f"([comment](https://github.com/{REPO}/pull/{PR}#issuecomment-1))",
        "### Prefilter (code, no LLM)",
        "workflow\\-change",
        "Coverage: complete",
        "### Dependency delta",
        "### Findings per pass",
        publish.UNTRUSTED_NOTE,
        publish.VERIFIED_NOTE,
        "### Token usage",
        "input 12000, output 900, cache write 11000, cache read 0, attempts 1",
        "total: input 36000",
        f"[Workflow run](https://github.com/{REPO}/actions/runs/{RUN_ID}/attempts/{ATTEMPT})",
        "The result that counts is the required workflow in the merge box.",
    ):
        assert text in s, text


def test_override_command_printed_for_waivable_only(tmp_path):
    r = run(tmp_path, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1
    assert f"/oc-review override {HEAD} {MB} <reason>" in r.summary
    r2 = run(tmp_path / "2", passes=clean_passes(supply_chain=[BLOCKING]), needs=needs_ok("failure"))
    assert "/oc-review override" not in r2.summary


# ---------------------------------------------------------------- stale


def test_stale_at_first_check_writes_nothing(tmp_path):
    r = run(tmp_path, FakeGitHub(head=OTHER), passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1
    assert r.gh.writes == []
    assert r.record["reasons"] == ["stale"]


def test_merge_base_moved_is_stale(tmp_path):
    r = run(tmp_path, FakeGitHub(merge_base=OTHER))
    assert (r.code, r.gh.writes) == (1, [])


def test_stale_before_summary_after_review(tmp_path):
    def push(gh, req):
        if req.method == "POST" and req.url.endswith("/reviews"):
            gh.head = OTHER

    r = run(tmp_path, FakeGitHub(after=push), passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1
    assert [urllib.parse.urlsplit(w.url).path for w in r.gh.writes] == [f"{API}/pulls/{PR}/reviews"]


def test_stale_before_review_writes_nothing(tmp_path):
    def push(gh, req):
        if req.method == "GET" and req.url.split("?")[0].endswith(f"/pulls/{PR}/comments"):
            gh.head = OTHER

    r = run(tmp_path, FakeGitHub(after=push), passes=clean_passes(supply_chain=[BLOCKING]))
    assert (r.code, r.gh.writes) == (1, [])


def test_stale_at_final_check_no_sticky_update(tmp_path):
    def push(gh, req):
        if req.method == "POST" and req.url.endswith(f"/issues/{PR}/comments"):
            gh.head = OTHER

    gh = FakeGitHub(after=push, runs=[{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 1, "path": WORKFLOW}])
    r = run(tmp_path, gh)
    assert r.code == 1
    assert len(r.gh.summary_bodies()) == 1  # the first summary, no update
    assert r.gh.paths("PATCH") == []


def test_snapshot_read_error_writes_nothing(tmp_path):
    gh = FakeGitHub(fail={("GET", f"{API}/pulls/{PR}", "1")})
    r = run(tmp_path, gh)
    assert (r.code, r.gh.writes) == (1, [])


@pytest.mark.parametrize("which", ["bundle", "pass"])
def test_stale_records_write_nothing(tmp_path, which):
    if which == "bundle":
        r = run(tmp_path, bundle=bundle_doc("stale"), passes={n: pass_doc(n, "stale") for n in verdict.PASS_NAMES})
    else:
        r = run(tmp_path, passes={n: pass_doc(n, "stale") for n in verdict.PASS_NAMES})
    assert (r.code, r.gh.writes) == (1, [])
    assert "stale" in r.record["reasons"]


def test_base_not_default_branch_fails_not_waivable(tmp_path):
    gh = FakeGitHub(default_branch="develop", issue_comments=[override(1)])
    r = run(tmp_path, gh)
    assert r.code == 1
    assert "base-not-default-branch (not waivable)" in r.summary


# ---------------------------------------------------------------- inline review


def test_inline_review_only_verified_and_eligible(tmp_path):
    passes = clean_passes(
        review=[
            finding(title="in diff head", line=10, quote="shell=True"),
            finding(title="in diff base", side="base", line=10, quote="line 10"),
            finding(title="outside diff", line=25, quote="line 25"),
            finding(title="unverified", line=10, quote="not there"),
            finding(title="title", file="/.pr/title", line=1, quote="Fix login"),
        ]
    )
    r = run(tmp_path, passes=passes)
    reviews = r.gh.bodies("POST", "/reviews")
    assert len(reviews) == 1
    rv = reviews[0]
    assert rv["event"] == "COMMENT" and rv["commit_id"] == HEAD
    assert set(rv) == {"commit_id", "event", "body", "comments"}
    got = sorted((c["path"], c["line"], c["side"]) for c in rv["comments"])
    assert got == [("src/app.py", 10, "LEFT"), ("src/app.py", 10, "RIGHT")]
    for c in rv["comments"]:
        assert re.match(r"<!-- oc-finding:[0-9a-f]{64} -->\n\n", c["body"])
        assert publish.UNTRUSTED_NOTE in c["body"]
    s = r.summary
    assert "in diff head. See the inline comment." in s
    assert "Outside the diff, summary only." in s
    assert "PR title or body, summary only." in s
    assert "### Unverified findings" in s and "Not verified: quote not found" in plain(s)


def test_inline_rename_base_side_uses_new_path(tmp_path):
    files = [{"path": "src/new.py", "old_path": "src/old.py", "status": "renamed",
              "base_content": BASE_TEXT, "head_content": HEAD_TEXT}]
    passes = clean_passes(review=[finding(file="src/old.py", side="base", line=10, quote="line 10")])
    r = run(tmp_path, bundle=bundle_doc(files=files), passes=passes)
    (rv,) = r.gh.bodies("POST", "/reviews")
    assert [(c["path"], c["side"]) for c in rv["comments"]] == [("src/new.py", "LEFT")]


def test_dedupe_by_bot_key_only(tmp_path):
    f1 = finding(title="first")
    f2 = finding(title="second", line=11, quote="line 11")
    key1 = publish.finding_key(verdict.cite_finding("review", f1, ()))
    key2 = publish.finding_key(verdict.cite_finding("review", f2, ()))
    gh = FakeGitHub(review_comments=[
        {"user": {"login": BOT}, "body": f"<!-- oc-finding:{key1} -->\n\nold"},
        {"user": {"login": "attacker"}, "body": f"<!-- oc-finding:{key2} -->"},
    ])
    r = run(tmp_path, gh, passes=clean_passes(review=[f1, f2, dict(f2)]))
    (rv,) = r.gh.bodies("POST", "/reviews")
    assert [c["line"] for c in rv["comments"]] == [11]  # key1 skipped; the spoofed key2 is not
    assert "first. See the inline comment from an earlier run." in r.summary


def test_no_review_when_nothing_new(tmp_path):
    f1 = finding(title="first")
    key = publish.finding_key(verdict.cite_finding("review", f1, ()))
    gh = FakeGitHub(review_comments=[{"user": {"login": BOT}, "body": f"<!-- oc-finding:{key} -->"}])
    r = run(tmp_path, gh, passes=clean_passes(review=[f1]))
    assert r.gh.bodies("POST", "/reviews") == []
    assert r.code == 0


def test_review_comments_read_with_paging(tmp_path):
    findings = [finding(title=f"t{i}", line=10) for i in range(3)]
    keys = [publish.finding_key(verdict.cite_finding("review", f, ())) for f in findings]
    filler = [{"user": {"login": BOT}, "body": "x"} for _ in range(150)]
    gh = FakeGitHub(review_comments=filler + [{"user": {"login": BOT}, "body": f"<!-- oc-finding:{k} -->"} for k in keys])
    r = run(tmp_path, gh, passes=clean_passes(review=findings))
    assert r.gh.bodies("POST", "/reviews") == []
    assert sum(p.endswith(f"/pulls/{PR}/comments") for p in r.gh.paths()) == 2


@pytest.mark.parametrize("status", [422, 500])
def test_rejected_review_moves_findings_to_summary(tmp_path, status):
    passes = clean_passes(supply_chain=[BLOCKING], review=[finding(title="bug here", explanation="details of the bug")])
    ok = run(tmp_path / "ok", passes=passes)
    bad = run(tmp_path / "bad", FakeGitHub(review_status=status), passes=passes)
    assert ok.code == bad.code == 1
    assert reason_codes(ok.summary) == reason_codes(bad.summary)
    assert "details of the bug" not in ok.summary
    assert "Inline comment not posted, shown here." in bad.summary
    assert "details of the bug" in bad.summary and "shell\\=True with input" in bad.summary
    if status == 422:
        assert "HTTP 422" in plain(bad.summary)


# ---------------------------------------------------------------- sticky


def test_sticky_updates_own_comment(tmp_path):
    gh = FakeGitHub(issue_comments=[api_comment(77, BOT, f"{verdict.STICKY_MARKER}\nold", type="Bot")])
    r = run(tmp_path, gh)
    assert r.gh.paths("POST") == []
    assert r.gh.paths("PATCH") == [f"{API}/issues/comments/77"]


def test_sticky_ignores_spoofed_marker(tmp_path):
    gh = FakeGitHub(issue_comments=[api_comment(66, "attacker", f"{verdict.STICKY_MARKER}\nfake pass")])
    r = run(tmp_path, gh)
    assert r.gh.paths("PATCH") == []
    assert r.gh.paths("POST") == [f"{API}/issues/{PR}/comments"]


def test_sticky_found_on_a_later_page(tmp_path):
    comments = [api_comment(i, "someone", "hi") for i in range(1, 121)]
    comments.append(api_comment(500, BOT, f"{verdict.STICKY_MARKER}\nold", type="Bot"))
    r = run(tmp_path, FakeGitHub(issue_comments=comments))
    assert r.gh.paths("PATCH") == [f"{API}/issues/comments/500"]


# ---------------------------------------------------------------- escaping and size


def test_untrusted_text_is_escaped_in_summary(tmp_path):
    nasty = (f"@user #12 GH-12 {'0123456789abcdef' * 2}abcdef01 [x](https://e) <img src=x> "
             f"bi‮di zero​width {GH_TOKEN}")
    path = "src/@user-#12-‮.py"
    files = [{"path": path, "old_path": None, "status": "added", "base_content": None, "head_content": "x = 1\n"}]
    short = "@user #12 GH-12 [x](https://e) <img src=x> bi\u202edi"
    passes = clean_passes(review=[finding(file=path, line=1, quote="x = 1", title=short, explanation=nasty)],
                          security=[finding(file="nope.py", title=short, explanation=nasty)])
    hb = [{"id": "bidi-control-characters", "level": "hard_block", "detail": "bidi", "file": path,
           "subject": nasty, "lines": [1], "count": 1}]
    r = run(tmp_path, bundle=bundle_doc(files=files, hard_blocks=hb, signals=hb), passes=passes)
    s = r.summary
    assert r.code == 1
    body = s.replace(verdict.STICKY_MARKER, "")
    assert GH_TOKEN not in s and "[REDACTED" in s
    assert "@user" not in s and f"@{ZWSP}user" in s
    assert not re.search(r"(?<!\\)#\d", s.replace(f"#{ZWSP}", ""))
    assert "#12" not in s and "GH-12" not in s
    assert "](https://e)" not in s and "https://e" not in s
    assert not re.search(r"(?<!\\)<img", body) and "\\<img" in body
    assert "[x]" not in body and "\\[x\\]" in body
    assert "‮" not in s and "zero​width" not in s
    plain = s.replace(HEAD, "").replace(MB, "").replace("f" * 64, "")
    assert not re.search(r"[0-9a-f]{7,}", plain)
    # The inline comment is escaped the same way.
    (rv,) = r.gh.bodies("POST", "/reviews")
    c = rv["comments"][0]["body"]
    assert GH_TOKEN not in c and "@user" not in c and "‮" not in c
    assert not re.search(r"(?<!\\)<img", c) and "[x]" not in c


def test_summary_under_limit_and_cut_in_order(tmp_path):
    long = "word " * 200
    def many(cat, sev, n, quote="shell=True", line=10):
        return [finding(cat, sev, title=f"{sev} {cat} {i}", explanation=long, quote=quote, line=line) for i in range(n)]

    passes = {
        "review": pass_doc("review", findings=many("bug", "low", 10, quote="missing", line=3)),
        "security": pass_doc("security", findings=many("security", "medium", 10)),
        "supply-chain": pass_doc("supply-chain", findings=many("malicious", "high", 5)
                                 + many("bug", "low", 10, quote="nope", line=4)),
    }
    changes = [{"path": "package-lock.json", "ecosystem": "npm", "name": f"pkg{i}", "old_versions": ["1.0.0"],
                "new_version": "1.0.1", "source": {"kind": "registry", "normalized": "registry.npmjs.org"},
                "direct": True, "has_install_script": False, "registry": None} for i in range(400)]
    signals = [{"id": "long-line", "level": "signal", "detail": "x" * 300, "file": f"f{i}.js", "subject": None,
                "lines": [1], "count": 1} for i in range(300)]
    bundle = bundle_doc(signals=signals, delta={"changes": changes, "new_global_sources": [], "failures": []})
    r = run(tmp_path, bundle=bundle, passes=passes)
    s = r.summary
    assert len(s) < publish.SUMMARY_MAX_CHARS
    assert publish.TRUNCATED_NOTE in s
    # Never cut: result, reasons, SHAs.
    assert "## OC Claude review: fail" in s and f"`{HEAD}`" in s
    assert "blocking-finding (waivable by override)" in s
    # Cut first: unverified findings; high findings stay.
    assert "### Unverified findings" in s
    assert "low bug 0" not in s
    for i in range(5):
        assert f"high malicious {i}" in s
    # The full JSON goes to the step summary.
    assert "Full record (the summary comment was cut)" in r.step
    assert "low bug 9" in r.step


def test_fit_cut_order():
    B = publish._Block
    blocks = [
        B("keep " * 10),
        B("u" * 500, publish.CUT_UNVERIFIED, "unverified"),
        B("l" * 500, publish.CUT_LOW_MEDIUM, "low"),
        B("d" * 500, publish.CUT_DEPENDENCY, "dependency"),
        B("s" * 500, publish.CUT_SIGNALS, "signals"),
    ]
    full, cut = publish._fit(blocks, 10_000)
    assert not cut
    text, cut = publish._fit(blocks, len(full) - 400)
    assert cut and "u" * 500 not in text and "l" * 500 in text
    assert len(text) <= len(full) - 400
    text, cut = publish._fit(blocks, len(full) - 1300)
    assert "u" * 500 not in text and "l" * 500 not in text and "d" * 500 not in text and "s" * 500 in text
    assert text.count(publish.TRUNCATED_NOTE) == 3
    # The size bookkeeping matches the joined text at every limit.
    many = [B("keep")] + [B("x" * (i % 7), publish.CUT_ORDER[i % 4], f"g{i % 3}") for i in range(40)]
    for limit in range(0, 400):
        text, _ = publish._fit(many, limit)
        assert text is None or len(text) <= limit


def test_fit_never_cuts_unranked_blocks():
    B = publish._Block
    blocks = [B("r" * 500), B("d" * 100, publish.CUT_DEPENDENCY, "dependency")]
    assert publish._fit(blocks, 300) == (None, True)


# ---------------------------------------------------------------- protected data (D8)


def hard_blocks(n, pad=0):
    return [{"id": "foreign-source", "level": "hard_block", "detail": "git dependency",
             "file": f"p{i:04d}/{'z' * pad}package.json", "subject": None, "lines": [], "count": 1}
            for i in range(n)]


def dep_delta(n):
    changes = [{"path": "package-lock.json", "ecosystem": "npm", "name": f"pkg{i}", "old_versions": ["1.0.0"],
                "new_version": "1.0.1", "source": {"kind": "registry", "normalized": "registry.npmjs.org"},
                "direct": True, "has_install_script": False, "registry": None} for i in range(n)]
    return {"changes": changes, "new_global_sources": [], "failures": []}


def full_record_from_log(out: str) -> dict:
    """The full record printed to the job log, between stop-commands markers."""
    m = re.search(r"^::stop-commands::([0-9a-f]{32})\n[^\n]*\n(.*)\n::\1::$", out, re.M | re.S)
    assert m, out[-2000:]
    return json.loads(m.group(2))


def test_reasons_kept_when_cuttable_data_is_cut(tmp_path, capsys):
    r = run(tmp_path, bundle=bundle_doc(hard_blocks=hard_blocks(60), delta=dep_delta(700)))
    s = r.summary
    assert r.code == 1
    assert publish.TRUNCATED_NOTE in s and "pkg699" not in s
    shown = re.findall(r"^- prefilter-hard-block \(not waivable\): foreign-source in p(\d{4})/", plain(s), re.M)
    assert shown == [f"{i:04d}" for i in range(60)]
    assert s.rstrip().endswith("The result that counts is the required workflow in the merge box.")


def test_reasons_that_do_not_fit_fail_closed(tmp_path, capsys):
    r = run(tmp_path, bundle=bundle_doc(hard_blocks=hard_blocks(400, pad=200)))
    s = r.summary
    assert r.code == 1
    assert len(s) < publish.SUMMARY_MAX_CHARS
    assert "## OC Claude review: fail" in s and publish.OVERFLOW_NOTE in s
    assert f"head SHA `{HEAD}`" in s and f"merge base `{MB}`" in s
    assert "- prefilter-hard-block (not waivable): 400 reason(s)" in s
    # No partial reason list: either every reason or none.
    assert "p0000" not in s
    rec = full_record_from_log(capsys.readouterr().out)
    shown = [x["detail"][len("foreign-source in p"):][:4] for x in rec["reasons"]]
    assert shown == [f"{i:04d}" for i in range(400)]
    assert r.record["result"] == "fail" and r.record["publish_error"]


def test_overrides_that_do_not_fit_fail_closed(tmp_path, capsys):
    comments = [override(i, reason=f"reason {i:03d} " + "y" * 240) for i in range(1, 301)]
    r = run(tmp_path, FakeGitHub(issue_comments=comments), passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1  # the override waives the finding, but the summary cannot show it
    s = r.summary
    assert publish.OVERFLOW_NOTE in s and "300 valid override(s)" in s
    rec = full_record_from_log(capsys.readouterr().out)
    assert [o["reason"][:10] for o in rec["overrides"]][-1] == "reason 300"
    assert len(rec["overrides"]) == 300 and rec["override_applied"] is True


def test_many_overrides_that_fit_are_all_listed(tmp_path):
    comments = [override(i, reason=f"reason {i:03d}") for i in range(1, 101)]
    r = run(tmp_path, FakeGitHub(issue_comments=comments), passes=clean_passes(supply_chain=[BLOCKING]),
            bundle=bundle_doc(delta=dep_delta(700)))
    assert r.code == 0
    s = r.summary
    assert publish.TRUNCATED_NOTE in s
    for i in range(1, 101):
        assert f"reason {i:03d} ([comment]" in s, i
    assert s.rstrip().endswith("The result that counts is the required workflow in the merge box.")


def test_cut_data_is_in_the_run_log(tmp_path, capsys):
    signals = [{"id": "long-line", "level": "signal", "detail": "x" * 300, "file": f"f{i}.js", "subject": None,
                "lines": [1], "count": 1} for i in range(300)]
    r = run(tmp_path, bundle=bundle_doc(signals=signals, delta=dep_delta(700)))
    s = r.summary
    assert r.code == 0
    assert f"item(s) {publish.TRUNCATED_NOTE}" in s and "pkg699" not in s and "f299.js" not in plain(s)
    rec = full_record_from_log(capsys.readouterr().out)
    assert [c["name"] for c in rec["dependency_delta"]["changes"]] == [f"pkg{i}" for i in range(700)]
    assert [x["file"] for x in rec["prefilter"]["signals"]][-1] == "f299.js"
    # Under the cap, the step summary has the same full record.
    assert "Full record (the summary comment was cut)" in r.step and '"pkg699"' in r.step


def test_full_record_over_step_summary_cap_names_the_job_log(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(publish, "STEP_SUMMARY_FULL_MAX", 1000)
    r = run(tmp_path, bundle=bundle_doc(delta=dep_delta(700)))
    assert '"pkg699"' not in r.step and "gate job log" in r.step
    assert full_record_from_log(capsys.readouterr().out)["dependency_delta"]["changes"][-1]["name"] == "pkg699"


# ---------------------------------------------------------------- write failures and late staleness


@pytest.mark.parametrize("trigger", ["runs", "permission"])
def test_stale_before_final_summary_update_writes_nothing(tmp_path, trigger):
    perm_reads = []

    def push(gh, req):
        path = urllib.parse.urlsplit(req.url).path
        if trigger == "runs" and req.method == "GET" and path == f"{API}/actions/runs":
            gh.head = OTHER
        if trigger == "permission" and "/collaborators/" in path:
            perm_reads.append(path)
            if len(perm_reads) == 2:  # the read at the final check
                gh.head = OTHER

    gh = FakeGitHub(after=push, runs=[{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 1, "path": WORKFLOW}])
    kw: dict[str, Any] = {}
    if trigger == "permission":
        gh.issue_comments = [override(1)]
        kw["passes"] = clean_passes(supply_chain=[BLOCKING])
    r = run(tmp_path, gh, **kw)
    assert r.code == 1
    assert len(r.gh.summary_bodies()) == 1 and "## OC Claude review: pass" in r.summary
    assert r.gh.paths("PATCH") == []
    assert "stale" in r.record["reasons"]


@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_refused_summary_write_fails_closed(tmp_path, method):
    gh = FakeGitHub()
    if method == "POST":
        gh.fail = {("POST", f"{API}/issues/{PR}/comments", "1")}
    else:
        gh.issue_comments = [api_comment(77, BOT, f"{verdict.STICKY_MARKER}\nold", type="Bot")]
        gh.fail = {("PATCH", f"{API}/issues/comments/77", "1")}
    r = run(tmp_path, gh)
    assert r.code == 1
    assert r.record["result"] == "fail" and r.record["publish_error"] == "the summary write failed"
    assert r.gh.paths().count(f"{API}/actions/runs") == 1  # the final reads still ran
    assert "publish_error" not in run(tmp_path / "ok").record


# ---------------------------------------------------------------- overrides


def test_override_from_fetched_data_and_permission_reads(tmp_path):
    gh = FakeGitHub(issue_comments=[
        override(1, MAINT),
        override(2, MAINT2),
        override(3, AUTHOR),  # PR author: rejected before any permission read
        api_comment(4, "random", "hello"),
        override(5, "reader", head=OTHER),  # wrong SHA: no permission read
    ])
    r = run(tmp_path, gh, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 0
    perms = sorted(p.split("/")[-2] for p in r.gh.paths() if "/collaborators/" in p)
    assert perms == sorted([MAINT, MAINT2] * 2)  # before the gate and at the final check
    assert f"by {MAINT}" in r.summary and "by admin\\-user" in r.summary


def test_timeline_not_read_fully_gives_no_override(tmp_path):
    events = [{"event": "labeled", "created_at": iso(T0)} for _ in range(150)]
    gh = FakeGitHub(issue_comments=[override(1)], timeline=events,
                    fail={("GET", f"{API}/issues/{PR}/timeline", "2")})
    r = run(tmp_path, gh, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1
    assert "Override applied" not in r.summary


def test_override_before_push_epoch_rejected(tmp_path):
    events = [{"event": "head_ref_force_pushed", "created_at": iso(T0 + timedelta(hours=2))}]
    gh = FakeGitHub(issue_comments=[override(1)], timeline=events)
    r = run(tmp_path, gh, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1


def test_permission_read_error_gives_no_override(tmp_path):
    gh = FakeGitHub(issue_comments=[override(1)], permissions={})
    r = run(tmp_path, gh, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1


def test_override_never_clears_hard_block(tmp_path):
    hb = [{"id": "foreign-source", "level": "hard_block", "detail": "git dep", "file": "package-lock.json",
           "subject": None, "lines": [], "count": 1}]
    r = run(tmp_path, FakeGitHub(issue_comments=[override(1)]), bundle=bundle_doc(hard_blocks=hb))
    assert r.code == 1
    assert "prefilter-hard-block (not waivable)" in r.summary


def test_grant_deleted_before_final_check(tmp_path):
    def delete_grant(gh, req):
        if req.method == "POST" and req.url.endswith(f"/issues/{PR}/comments"):
            gh.issue_comments[:] = [c for c in gh.issue_comments if c["id"] != 1]

    gh = FakeGitHub(issue_comments=[override(1)], after=delete_grant)
    r = run(tmp_path, gh, passes=clean_passes(supply_chain=[BLOCKING]))
    assert r.code == 1
    assert len(r.gh.summary_bodies()) == 2  # pass summary, then the update to fail
    assert "## OC Claude review: fail" in r.summary


# ---------------------------------------------------------------- final check


def test_newer_run_supersedes_and_updates_summary(tmp_path):
    gh = FakeGitHub(runs=[{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 5, "path": WORKFLOW}])
    r = run(tmp_path, gh)
    assert r.code == 1
    first, last = r.gh.summary_bodies()
    assert "## OC Claude review: pass" in first
    assert "## OC Claude review: fail" in last and "superseded (not waivable)" in last
    assert r.gh.paths("PATCH")  # the update edits the comment the run posted


def test_runs_paged_over_several_pages(tmp_path):
    runs = [{"id": i, "path": "other.yml"} for i in range(1, 7)] + [{"id": RUN_ID, "path": WORKFLOW},
                                                                   {"id": RUN_ID + 1, "path": WORKFLOW}]
    gh = FakeGitHub(runs=runs, runs_per_page=3)
    r = run(tmp_path, gh)
    assert r.code == 1
    assert sum(p.endswith("/actions/runs") for p in r.gh.paths()) == 3
    assert "newer run 1001" in plain(r.summary)


def test_runs_other_workflows_do_not_supersede(tmp_path):
    runs = [{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 9, "path": ".github/workflows/ci.yml"}]
    r = run(tmp_path, FakeGitHub(runs=runs, runs_per_page=1))
    assert r.code == 0


@pytest.mark.parametrize("kind", ["page-error", "short-total", "no-path", "bad-id"])
def test_run_list_read_in_part_is_superseded(tmp_path, kind):
    runs = [{"id": RUN_ID, "path": WORKFLOW}, {"id": 1, "path": "ci.yml"}]
    gh = FakeGitHub(runs=runs, runs_per_page=1)
    if kind == "page-error":
        gh.fail = {("GET", f"{API}/actions/runs", "2")}
    elif kind == "short-total":
        gh.runs_total = 3
    elif kind == "no-path":
        gh.runs = [{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 1}]
    else:
        gh.runs = [{"id": RUN_ID, "path": WORKFLOW}, {"id": "x", "path": "ci.yml"}]
    r = run(tmp_path, gh)
    assert r.code == 1
    assert "superseded (not waivable)" in r.summary


# ---------------------------------------------------------------- reasons and exit code


@pytest.mark.parametrize(
    "case, expected",
    [
        ("clean", 0),
        ("blocking", 1),
        ("blocking+override", 0),
        ("bug-only", 0),
        ("job-failure", 1),
        ("size-gate", 1),
        ("size-gate+override", 0),
        ("hard-block+override", 1),
    ],
)
def test_exit_code_zero_only_for_pass(tmp_path, case, expected):
    kw: dict[str, Any] = {}
    gh = FakeGitHub()
    if "override" in case:
        gh.issue_comments = [override(1)]
    if case.startswith("blocking"):
        kw["passes"] = clean_passes(supply_chain=[BLOCKING])
    elif case == "bug-only":
        kw["passes"] = clean_passes(review=[finding("bug", "critical")])
    elif case == "job-failure":
        kw["needs"] = {**needs_ok(), "analyze": {"result": "failure"}}
    elif case.startswith("size-gate"):
        kw["bundle"] = bundle_doc("skipped-size")
        kw["passes"] = {n: pass_doc(n, "skipped-size") for n in verdict.PASS_NAMES}
    elif case.startswith("hard-block"):
        kw["bundle"] = bundle_doc(hard_blocks=[{"id": "too-new", "level": "hard_block", "detail": "new"}])
    r = run(tmp_path, gh, **kw)
    assert r.code == expected
    assert r.record["result"] == ("pass" if expected == 0 else "fail")


def test_size_gate_records_show_reason(tmp_path):
    r = run(tmp_path, bundle=bundle_doc("skipped-size"),
            passes={n: pass_doc(n, "skipped-size") for n in verdict.PASS_NAMES})
    assert reason_codes(r.summary) == {"size-gate"}
    assert "too large for automatic review" in plain(r.summary)


def test_missing_needs_and_outcome_fail_with_summary(tmp_path):
    needs = {"collect": {"result": "success"}, "dependency-review": {"result": "success", "outputs": {}}}
    r = run(tmp_path, needs=needs)
    assert r.code == 1
    s = r.summary
    assert "job-result (not waivable): analyze: missing" in plain(s)
    assert "dependency-review (not waivable): step outcome missing" in plain(s)


def test_outcome_from_env_and_conflict(tmp_path):
    needs = needs_ok()
    del needs["dependency-review"]["outputs"]["outcome"]
    assert run(tmp_path / "a", needs=needs, outcome_env="success").code == 0
    r = run(tmp_path / "b", outcome_env="failure")
    assert r.code == 1 and "step outcome conflicting outcomes" in plain(r.summary)


def test_dependency_review_failure_with_job_success(tmp_path):
    r = run(tmp_path, needs=needs_ok("failure"), gh=FakeGitHub(issue_comments=[override(1)]))
    assert r.code == 1
    assert "dependency-review (not waivable): step outcome failure" in plain(r.summary)


@pytest.mark.parametrize("missing", ["bundle", "review", "supply-chain", "all"])
def test_missing_artifact_dirs_fail_and_still_post_summary(tmp_path, missing):
    if missing == "bundle":
        r = run(tmp_path, bundle=None)
    elif missing == "all":
        r = run(tmp_path, bundle=None, passes={})
    else:
        passes = clean_passes()
        passes[missing] = None
        r = run(tmp_path, passes=passes)
    assert r.code == 1
    s = r.summary
    assert "artifact (not waivable)" in s
    if missing in ("bundle", "all"):
        assert f"No valid bundle. Event head SHA `{HEAD}`" in s
    else:
        assert f"missing pass record {missing}" in plain(s)


def test_missing_bundle_and_pushed_head_writes_nothing(tmp_path):
    r = run(tmp_path, FakeGitHub(head=OTHER), bundle=None)
    assert (r.code, r.gh.writes) == (1, [])


def test_digest_mismatch_is_artifact_reason(tmp_path):
    r = run(tmp_path, digests={"security": "0" * 64})
    assert r.code == 1
    assert "pass record" in plain(r.summary) and "digest mismatch" in plain(r.summary)


def test_spend_limit_reason_from_meta(tmp_path):
    passes = clean_passes()
    meta = {"reason": "workspace spend limit reached", "model": None, "stop_reason": None,
            "request_schema_sha256": "f" * 64, "usage": None}
    passes["security"] = pass_doc("security", "failed", meta=meta)
    r = run(tmp_path, passes=passes, gh=FakeGitHub(issue_comments=[override(1)]))
    assert r.code == 1
    s = r.summary
    assert "pass-records (not waivable): pass security failed: workspace spend limit reached" in plain(s)
    assert "#### security: failed, workspace spend limit reached" in plain(s)
    assert "- security: no usage recorded" in s
    rec = r.record
    assert rec["passes"]["review"]["usage"] == USAGE
    assert rec["passes"]["security"]["usage"] == {}
    assert "pass-records" in rec["reasons"]
    text = json.dumps(rec).lower()
    for word in ("cost", "usd", "price", "$", "dollar", "eur"):
        assert word not in text


# ---------------------------------------------------------------- stale result record


def _stale_after(point):
    """A hook that makes the run stale at one point after the initial gate."""

    def hook(gh, req):
        path = urllib.parse.urlsplit(req.url).path
        if point == "review" and req.method == "GET" and path == f"{API}/pulls/{PR}/comments":
            gh.head = OTHER
        if point == "summary" and req.method == "POST" and path.endswith("/reviews"):
            gh.head = OTHER
        if point == "review-read-error" and req.method == "GET" and path == f"{API}/pulls/{PR}/comments":
            gh.fail.add(("GET", f"{API}/pulls/{PR}", "1"))
        if point == "summary-read-error" and req.method == "POST" and path.endswith("/reviews"):
            gh.fail.add(("GET", f"{API}/pulls/{PR}", "1"))

    return hook


@pytest.mark.parametrize("point", ["review", "summary", "review-read-error", "summary-read-error"])
def test_stale_exit_records_fail_not_the_earlier_pass(tmp_path, point):
    # A low inline finding: the initial gate result is pass.
    r = run(tmp_path, FakeGitHub(after=_stale_after(point)), passes=clean_passes(review=[finding()]))
    assert r.code == 1
    assert r.gh.summary_bodies() == []
    assert r.record["result"] == "fail"
    assert "stale" in r.record["reasons"]


def test_stale_reason_code_alone_records_fail():
    passed = verdict.GateResult(verdict.PASS, RUN_ID, (), (), None, (), False)
    assert json.loads(publish._step_summary_record(CTX, passed, []))["result"] == "pass"
    assert json.loads(publish._step_summary_record(CTX, passed, ["stale"]))["result"] == "fail"


# ---------------------------------------------------------------- full record after the final render


def _final_render_uncut(monkeypatch):
    """The first summary is cut; the final one (after the final check) fits."""
    real = publish.render_summary
    calls = []

    def render(*args, **kw):
        calls.append(1)
        if len(calls) > 1:
            kw["limit"] = 10**9
        return real(*args, **kw)

    monkeypatch.setattr(publish, "render_summary", render)


def test_final_summary_not_cut_drops_initial_full_record(tmp_path, capsys, monkeypatch):
    _final_render_uncut(monkeypatch)
    gh = FakeGitHub(runs=[{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 5, "path": WORKFLOW}])
    r = run(tmp_path, gh, bundle=bundle_doc(delta=dep_delta(700)))
    first, last = r.gh.summary_bodies()
    assert publish.TRUNCATED_NOTE in first and publish.TRUNCATED_NOTE not in last
    assert r.code == 1 and r.record["result"] == "fail"
    # The comment as it stands is not cut, so the step summary has no full record.
    assert "Full record (the summary comment was cut)" not in r.step and '"pkg699"' not in r.step
    assert "gate job log" not in r.step


def test_final_summary_update_failed_keeps_initial_full_record(tmp_path, capsys, monkeypatch):
    _final_render_uncut(monkeypatch)
    gh = FakeGitHub(runs=[{"id": RUN_ID, "path": WORKFLOW}, {"id": RUN_ID + 5, "path": WORKFLOW}])

    def refuse_update(gh, req):
        if req.method == "POST" and urllib.parse.urlsplit(req.url).path == f"{API}/issues/{PR}/comments":
            gh.fail.add(("PATCH", f"{API}/issues/comments/{gh.next_id}", "1"))

    gh.after = refuse_update
    r = run(tmp_path, gh, bundle=bundle_doc(delta=dep_delta(700)))
    assert r.code == 1
    assert r.gh.paths("PATCH")  # the update was tried and refused
    # The comment still holds the cut first summary, so its full record stays.
    assert "Full record (the summary comment was cut)" in r.step and '"pkg699"' in r.step


# ---------------------------------------------------------------- bounded diff (inline hunks)


class _BoundedMatcher(linediff._CountingMatcher):
    """Fails a test that runs a line diff past the size budget."""

    def __init__(self, a, b, allowance):
        assert len(a) * len(b) <= linediff.DIFF_BUDGET, (len(a), len(b))
        super().__init__(a, b, allowance)


@pytest.fixture
def bounded_diff(monkeypatch):
    monkeypatch.setattr(linediff, "_CountingMatcher", _BoundedMatcher)


def _one_file(base: str, head: str) -> dict:
    return bundle_doc(files=[{"path": "big.txt", "old_path": None, "status": "modified",
                              "base_content": base, "head_content": head}])


def _reached_the_end(r: Run) -> None:
    assert r.gh.summary_bodies()  # the summary was posted
    assert r.gh.paths().count(f"{API}/actions/runs") == 1  # and the final check ran
    assert r.record["run_id"] == RUN_ID


def test_large_common_prefix_gets_exact_inline_hunk(tmp_path, bounded_diff):
    base = "x\n" * 100_000
    head = base + "y\n"
    f = verdict.changed_file("big.txt", base_raw=base, head_raw=head)
    assert (f.base_hunks, f.head_hunks) == (((99_998, 100_000),), ((99_998, 100_001),))
    passes = clean_passes(review=[finding(file="big.txt", line=100_001, quote="y")])
    r = run(tmp_path, bundle=_one_file(base, head), passes=passes)
    (rv,) = r.gh.bodies("POST", "/reviews")
    assert [(c["path"], c["line"], c["side"]) for c in rv["comments"]] == [("big.txt", 100_001, "RIGHT")]
    assert r.code == 0
    _reached_the_end(r)


def test_change_inside_repeated_lines_gets_exact_hunk(bounded_diff):
    base = "x\n" * 20_000
    head = "x\n" * 10_000 + "y\n" + "x\n" * 10_000
    assert verdict.hunks_from_texts(base, head) == (((9_998, 10_003),), ((9_998, 10_004),))


def test_diff_past_budget_sends_findings_to_summary(tmp_path, bounded_diff):
    n = 6_000  # middle 6,002 x 6,002 lines: past the budget
    assert (n + 2) ** 2 > linediff.DIFF_BUDGET
    base = "a\n" + "x\n" * n + "b\n"
    head = "c\n" + "x\n" * n + "d\n"
    assert verdict.hunks_from_texts(base, head) == ((), ())
    blocking = finding("malicious", "high", file="big.txt", line=1, quote="c", title="Bad first line")
    low = finding(file="big.txt", line=n + 2, quote="d", title="Low last line")
    r = run(tmp_path, bundle=_one_file(base, head), passes=clean_passes(review=[low], supply_chain=[blocking]))
    assert r.gh.bodies("POST", "/reviews") == []  # no exact hunk, so nothing inline
    s = r.summary
    assert "Bad first line" in s and "Low last line" in s  # every finding kept
    assert r.code == 1 and "blocking-finding" in reason_codes(s)  # and it still blocks
    _reached_the_end(r)


def test_low_entropy_file_past_the_work_budget_reaches_the_end(tmp_path):
    n = 2_000
    base = "a\n" * n
    head = "c\n" + "".join("a\n" if i % 2 == 0 else "b\n" for i in range(1, n - 1)) + "d\n"
    f = verdict.changed_file("big.txt", base_raw=base, head_raw=head)
    assert (f.base_hunks, f.head_hunks, f.no_hunks_reason) == ((), (), linediff.PAST_FILE_WORK_BUDGET)
    low = finding(file="big.txt", line=n, quote="d", title="Low last line")
    r = run(tmp_path, bundle=_one_file(base, head), passes=clean_passes(review=[low]))
    assert r.gh.bodies("POST", "/reviews") == []  # no exact hunk, so nothing inline
    assert "Low last line" in r.summary
    _reached_the_end(r)


def test_hunk_work_budget_is_shared_by_the_run(monkeypatch, capsys):
    base = "c\n" + "".join("a\n" if i % 2 == 0 else "b\n" for i in range(1, 299)) + "d\n"
    head = "e\n" + "".join("a\n" if (i // 2) % 2 == 0 else "b\n" for i in range(1, 299)) + "f\n"
    probe = linediff.WorkBudget()
    exact = verdict.hunks_from_texts(base, head, work=probe)
    steps = linediff.RUN_WORK_BUDGET - probe.left
    assert exact != ((), ()) and 0 < steps < linediff.FILE_WORK_BUDGET
    monkeypatch.setattr(linediff, "RUN_WORK_BUDGET", steps + steps // 2)
    doc = bundle_doc(files=[{"path": p, "old_path": None, "status": "modified", "base_content": base,
                             "head_content": head} for p in ("a.txt", "b.txt", "c.txt")])
    by_path = {f.path: f for f in publish.bundle_files(verdict.ArtifactRead(doc))}
    a = by_path["a.txt"]
    assert ((a.base_hunks, a.head_hunks), a.no_hunks_reason) == (exact, None)
    for p in ("b.txt", "c.txt"):
        f = by_path[p]
        assert (f.base_hunks, f.head_hunks, f.no_hunks_reason) == ((), (), linediff.PAST_RUN_WORK_BUDGET)
    err = capsys.readouterr().err
    assert "'b.txt'" in err and "'c.txt'" in err and "'a.txt'" not in err


def test_collect_patch_past_budget_is_one_middle_hunk(bounded_diff):
    base = "a\n" + "x\n" * 6_000 + "b\n"
    head = "c\n" + "x\n" * 6_000 + "d\n"
    patch, adds, dels = collect.unified_diff(base, head)
    assert (adds, dels) == (6_002, 6_002)
    assert patch.startswith("@@ -1,6002 +1,6002 @@\n")


# ---------------------------------------------------------------- never


SRC = Path(publish.__file__).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "forbidden",
    ["APPROVE", "REQUEST_CHANGES", "/merge", '"PUT"', "'PUT'", '"DELETE"', "'DELETE'", "/labels",
     "check-runs", "check-suites", "/lock", '"state"', "/requested_reviewers", "/dismissals"],
)
def test_no_forbidden_call_in_module(forbidden):
    assert forbidden not in SRC
    assert forbidden not in Path(verdict.__file__).read_text(encoding="utf-8")


def test_write_refuses_other_routes():
    gh = FakeGitHub()
    api = GitHubApi("t", gh)
    for method, path, body in [
        ("PATCH", f"{API}/pulls/{PR}", {"title": "x"}),
        ("POST", f"{API}/pulls/{PR}/merge", {}),
        ("POST", f"{API}/issues/{PR}/labels", {}),
        ("PUT", f"{API}/pulls/{PR}/merge", {}),
        ("POST", f"{API}/check-runs", {}),
        ("POST", f"{API}/pulls/{PR}/reviews", {"event": "APPROVE"}),
        ("POST", f"{API}/pulls/{PR}/reviews", {"event": "REQUEST_CHANGES"}),
        ("POST", f"{API}/pulls/{PR}/reviews", {"event": "COMMENT", "state": "x"}),
        ("POST", f"{API}/pulls/{PR}/reviews", {}),
    ]:
        with pytest.raises(publish.WriteError):
            api.write(method, path, body)
    assert gh.requests == []


def test_default_transport_sends_body():
    seen = {}

    class Resp(io.BytesIO):
        status = 201
        url = "https://api.github.com/x"
        headers: dict = {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout):
            seen["data"], seen["method"] = req.data, req.get_method()
            return Resp(b'{"id": 1}')

    req = HttpRequest("POST", "https://api.github.com/x", {}, 100, 5.0, b'{"body":"hi"}')
    resp = collect.default_transport(req, opener=Opener())
    assert (seen["method"], seen["data"], resp.status) == ("POST", b'{"body":"hi"}', 201)
    assert HttpRequest("GET", "https://api.github.com/x", {}, 1, 1.0).body is None


# ---------------------------------------------------------------- CLI


def test_main_end_to_end(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    digests = write_data(data, bundle_doc(), clean_passes())
    event = {"repository": {"id": REPO_ID, "full_name": REPO},
             "pull_request": {"number": PR, "head": {"sha": HEAD}, "user": {"login": AUTHOR}}}
    (tmp_path / "event.json").write_text(json.dumps(event))
    (tmp_path / "needs.json").write_text(json.dumps(needs_ok()))
    env = {"GITHUB_EVENT_PATH": str(tmp_path / "event.json"), "GITHUB_TOKEN": "t", "GITHUB_RUN_ID": str(RUN_ID),
           "GITHUB_RUN_ATTEMPT": str(ATTEMPT), "GITHUB_SERVER_URL": "https://github.com",
           "GITHUB_STEP_SUMMARY": str(tmp_path / "step.md"), "DEPENDENCY_REVIEW_OUTCOME": "success"}
    for k, v in publish.DIGEST_ENV.items():
        env[v] = digests[k]
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    gh = FakeGitHub()
    argv = ["--data-dir", str(data), "--needs-json", str(tmp_path / "needs.json")]
    assert publish.main(argv, transport=gh) == 0
    assert gh.summary_bodies()
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")  # envelopes are for attempt 1
    assert publish.main(argv, transport=FakeGitHub()) == 1
    monkeypatch.delenv("GITHUB_EVENT_PATH")
    assert publish.main(argv, transport=FakeGitHub()) == 1


def test_context_rejects_bad_server_url():
    event = {"repository": {"id": REPO_ID, "full_name": REPO},
             "pull_request": {"number": PR, "head": {"sha": HEAD}, "user": {"login": AUTHOR}}}
    ctx = PublishContext.from_event(event, run_id=1, run_attempt=1, server_url="javascript:alert(1)")
    assert ctx.server_url == "https://github.com"
    with pytest.raises(collect.CollectError):
        PublishContext.from_event({**event, "pull_request": {"number": PR, "head": {"sha": HEAD}}},
                                  run_id=1, run_attempt=1)
