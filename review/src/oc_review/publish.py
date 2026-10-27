"""Publisher: the gate job. Escaping, GitHub comments, final check, exit code.

The gate job runs no LLM and holds no Anthropic credential. It reads the
artifacts by fixed directory and producer digest, re-validates the snapshot,
reads the override inputs, computes the gate (`verdict.compute_gate`), then
writes, in this order, each after a fresh snapshot check:

    inline review (event COMMENT) -> sticky summary -> final check -> exit code

A stale run writes nothing more and exits 1. The write targets (repository,
PR number) come from the trusted event payload only. The only writes are a
`COMMENT` review, a new issue comment and a PATCH of the bot's own sticky
comment (`GitHubApi.write` refuses every other route). The bot never
approves, requests changes, merges, closes, labels or edits the PR (K-1).

Escaping. Spec "Publishing (code)": every untrusted string (from Claude, and from the PR:
title, paths, package names, URLs, prefilter evidence) is escaped before it is
posted. `escape_text` does these steps, in this order:

1. Remove control, format and invisible characters (bidi controls, zero-width
   characters, Unicode tags, variation selectors). Line breaks become `\\n`.
   Long runs of combining marks are cut.
2. Redact credential-like strings (`render.redact_text`), before any cut, so
   no part of a secret survives truncation.
3. Single-line text: every line break becomes a space. Multi-line text: lines
   are stripped and blank lines dropped, so the result is one paragraph.
4. Truncate to the fixed limit (counted in characters after steps 1-3).
5. Break pings and autolinks with a zero-width space (U+200B): after every
   `@`, between `:` and `//`, after `www`, after `#` and `GH-` before a digit,
   and after every 6 characters of a run of 7+ hex characters (commit SHAs).
   This comes after the cut, so a cut cannot make a new reference.
6. Backslash-escape every ASCII punctuation character, so no Markdown link,
   image, HTML, autolink, emphasis, heading, list, table or entity can form.
   Multi-line text joins lines with a Markdown hard break (`\\` + newline).

The result is for Markdown prose only, not for code spans or code blocks
(backslashes show there).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import string
import sys
import unicodedata
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oc_review import collect, envelope, linediff, snapshot, verdict
from oc_review.render import redact_text

ZWSP = "​"
TRUNCATED = "… \\[truncated\\]"

# Fixed limits in characters, per field. Claude fields match the findings
# schema maxLength. PR fields use GitHub's own limits where they exist.
LIMITS: dict[str, int] = {
    # From Claude
    "summary": 1500,
    "title": 120,
    "explanation": 1200,
    "quote": 300,
    "file": 400,
    # From the PR and from code that read it
    "pr_title": 256,
    "path": 400,
    "package_name": 214,
    "version": 128,
    "url": 300,
    "evidence": 300,
    "login": 39,
    "label": 100,
    "reason": 300,
    "ref": 255,
    "model": 100,
}
# Fields shown as several lines. All others are one line.
MULTILINE = frozenset({"summary", "explanation", "quote"})

# Combining marks kept after one base character ("Zalgo" text is cut).
MAX_COMBINING = 4

_PUNCT = frozenset(string.punctuation)
_LINE_BREAKS = re.compile(r"\r\n|[\r\n\x0b\x0c\x1c-\x1e\x85  ]")
_AT_SIGNS = ("@", "＠", "﹫")  # @, fullwidth @, small @
_DEFANG = re.compile(r"(?<=:)(?=//)|(?<=\bwww)(?=\.)|(?<=#)(?=\d)|(?<=\bgh-)(?=\d)", re.IGNORECASE)
# GitHub links a bare commit SHA, full or short (7+ hex characters), also in
# `user@sha` and `owner/repo@sha` forms. Every run of 7 or more hex characters
# gets a ZWSP after each 6, so no part is long enough. No word-boundary test:
# GitHub's exact rule is not known, so any such run is broken.
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{7,}")
_HEX_CHUNK = 6


def _break_hex(m: re.Match[str]) -> str:
    run = m.group()
    return ZWSP.join(run[i : i + _HEX_CHUNK] for i in range(0, len(run), _HEX_CHUNK))


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    return (
        unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn")
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or cp in (0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0)
    )


def _strip_controls(text: str) -> str:
    text = _LINE_BREAKS.sub("\n", text).replace("\t", " ")
    out: list[str] = []
    marks = 0
    for ch in text:
        if ch == "\n":
            out.append(ch)
            marks = 0
        elif _invisible(ch):
            continue
        elif unicodedata.category(ch) in ("Mn", "Me"):
            marks += 1
            if marks <= MAX_COMBINING:
                out.append(ch)
        else:
            out.append(ch)
            marks = 0
    return "".join(out)


def _escape_line(line: str) -> str:
    line = _HEX_RUN.sub(_break_hex, _DEFANG.sub(ZWSP, line))
    out: list[str] = []
    for ch in line:
        if ch in _PUNCT:
            out.append("\\" + ch)
        else:
            out.append(ch)
        if ch in _AT_SIGNS:
            out.append(ZWSP)
    return "".join(out)


def escape_text(text: str, limit: int, *, multiline: bool = False) -> str:
    """Escape one untrusted string for Markdown prose in a GitHub comment.

    `limit` counts characters of the cleaned text. The result is at most
    `3 * limit + len(TRUNCATED)` characters long.
    """
    if not isinstance(text, str):
        raise TypeError("escape_text takes a str")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive int")
    text = redact_text(_strip_controls(text))
    lines = [" ".join(line.split()) for line in text.split("\n")]
    lines = [line for line in lines if line]
    joined = "\n".join(lines) if multiline else " ".join(lines)
    cut = len(joined) > limit
    if cut:
        joined = joined[:limit].rstrip()
    escaped = "\\\n".join(_escape_line(line) for line in joined.split("\n"))
    return escaped + TRUNCATED if cut else escaped


def escape_field(kind: str, text: str) -> str:
    """`escape_text` with the fixed limit and line mode for a field kind."""
    if kind not in LIMITS:
        raise KeyError(f"no limit for field kind {kind!r}")
    return escape_text(text, LIMITS[kind], multiline=kind in MULTILINE)


def _esc(kind: str, value: Any) -> str:
    """`escape_field` for any value; a non-string becomes its JSON text."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=True, default=str)
    return escape_field(kind, value)


# ---------------------------------------------------------------------------
# GitHub client: reads, and the three allowed writes
# ---------------------------------------------------------------------------

REVIEW_EVENT = "COMMENT"
WRITE_MAX_BYTES = 1024 * 1024
PERMISSION_MAX_BYTES = 64 * 1024

# The only writes the gate job makes (spec "Publishing (code)", K-1).
_WRITE_ROUTES = (
    ("POST", re.compile(r"/repos/[^/]+/[^/]+/pulls/[1-9][0-9]*/reviews")),
    ("POST", re.compile(r"/repos/[^/]+/[^/]+/issues/[1-9][0-9]*/comments")),
    ("PATCH", re.compile(r"/repos/[^/]+/[^/]+/issues/comments/[1-9][0-9]*")),
)
_REVIEW_KEYS = frozenset({"commit_id", "event", "body", "comments"})


class WriteError(collect.HttpError):
    """A write was refused by this module or failed at GitHub."""


class GitHubApi(collect.GitHubClient):
    """`collect.GitHubClient` plus paging of object-wrapped lists and the
    publisher's writes. Writes are never retried: a retried POST could post
    twice."""

    def get_wrapped_pages(
        self,
        path: str,
        key: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_bytes: int = collect.PAGE_MAX_BYTES,
        max_pages: int = collect.MAX_PAGES,
    ) -> tuple[list[Any], int]:
        """Every item of a list endpoint whose pages are `{total_count, <key>: [...]}`
        (for example `workflow_runs`), and the largest `total_count` seen.

        Fails like `get_pages` on a bad page, a bad Link header, a next link to
        another host or more than `max_pages` pages.
        """
        url = self._url(path, {"per_page": 100, **(params or {})})
        items: list[Any] = []
        total = 0
        for _ in range(max_pages):
            resp = self._get(url, accept=collect.ACCEPT_JSON, max_bytes=max_bytes)
            try:
                page = envelope.parse_json(resp.body)
            except envelope.EnvelopeError as exc:
                raise collect.HttpError(f"{path}: {exc}") from exc
            if not isinstance(page, Mapping) or not isinstance(page.get(key), list):
                raise collect.HttpError(f"{path}: page has no {key} list")
            count = page.get("total_count")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise collect.HttpError(f"{path}: page has no total_count")
            total = max(total, count)
            items.extend(page[key])
            nxt = _next_page(resp, path)
            if nxt is None:
                return items, total
            url = nxt
        raise collect.HttpError(f"{path}: more than {max_pages} pages")

    def write(self, method: str, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """POST or PATCH one of `_WRITE_ROUTES`. Returns the response object."""
        if not any(method == m and rx.fullmatch(path) for m, rx in _WRITE_ROUTES):
            raise WriteError(f"write not allowed: {method} {path[:200]}")
        if path.endswith("/reviews") and (
            body.get("event") != REVIEW_EVENT or not set(body) <= _REVIEW_KEYS
        ):
            raise WriteError("a review must have event COMMENT and no other fields")
        headers = {
            "Accept": collect.ACCEPT_JSON,
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": "oc-claude-review",
            "X-GitHub-Api-Version": collect.API_VERSION,
        }
        data = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        url = self._url(path, None)
        request = collect.HttpRequest(method, url, headers, WRITE_MAX_BYTES, self._timeout, data)
        try:
            resp = self._transport(request)
        except OSError as exc:
            raise WriteError(f"{method} {path}: {type(exc).__name__}") from exc
        served = urllib.parse.urlsplit(resp.url)
        if served.scheme != "https" or served.hostname != collect.API_HOST or served.port is not None:
            raise WriteError(f"{method} {path}: response came from another host")
        if resp.status not in (200, 201):
            raise WriteError(f"{method} {path}: HTTP {resp.status}", resp.status)
        if len(resp.body) > WRITE_MAX_BYTES:
            raise WriteError(f"{method} {path}: response is over the byte cap", resp.status)
        try:
            doc = envelope.parse_json(resp.body)
        except envelope.EnvelopeError as exc:
            raise WriteError(f"{method} {path}: {exc}", resp.status) from exc
        if not isinstance(doc, Mapping):
            raise WriteError(f"{method} {path}: response is not an object", resp.status)
        return doc


def _next_page(resp: collect.HttpResponse, path: str) -> str | None:
    link = resp.headers.get("link")
    if link is None:
        return None
    try:
        nexts = [uri for uri, rels in collect.parse_link_header(link) if "next" in rels]
    except ValueError as exc:
        raise collect.HttpError(f"{path}: {exc}") from exc
    if not nexts:
        return None
    if len(nexts) > 1:
        raise collect.HttpError(f"{path}: more than one next page link")
    nxt = urllib.parse.urlsplit(nexts[0])
    if nxt.scheme != "https" or nxt.hostname != collect.API_HOST or nxt.port is not None:
        raise collect.HttpError(f"{path}: next page link points to another host")
    return nexts[0]


# ---------------------------------------------------------------------------
# Trusted inputs
# ---------------------------------------------------------------------------

DEFAULT_SERVER_URL = "https://github.com"
_SERVER_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+")
_LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
# Name of the dependency-review job output that holds the step outcome (1c).
DEPENDENCY_REVIEW_OUTPUT = "outcome"
DIGEST_ENV = {
    "bundle": "BUNDLE_DIGEST",
    "review": "REVIEW_DIGEST",
    "security": "SECURITY_DIGEST",
    "supply-chain": "SUPPLY_CHAIN_DIGEST",
}


@dataclass(frozen=True)
class PublishContext:
    """Write targets and run identity, from the trusted event and the runner only."""

    repository: str  # owner/name
    repository_id: int
    pr_number: int
    head_sha: str  # from the event; used only when there is no valid bundle
    pr_author: str
    run_id: int
    run_attempt: int
    server_url: str = DEFAULT_SERVER_URL

    @classmethod
    def from_event(
        cls, event: Mapping[str, Any], *, run_id: int, run_attempt: int, server_url: str | None = None
    ) -> PublishContext:
        ec = collect.EventContext.from_event(event)
        try:
            author = event["pull_request"]["user"]["login"]
        except (KeyError, TypeError) as exc:
            raise collect.CollectError(f"event payload is missing {exc}") from exc
        if not isinstance(author, str) or not author:
            raise collect.CollectError("event PR author login is not a string")
        for value, what in ((run_id, "run id"), (run_attempt, "run attempt")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise collect.CollectError(f"{what} is not a positive integer")
        server = server_url if server_url and _SERVER_URL_RE.fullmatch(server_url) else DEFAULT_SERVER_URL
        return cls(ec.repository, ec.repository_id, ec.pr_number, ec.head_sha, author, run_id, run_attempt, server)

    @property
    def run_context(self) -> verdict.RunContext:
        return verdict.RunContext(self.repository_id, self.pr_number, self.run_id, self.run_attempt)

    @property
    def repo_path(self) -> str:
        owner, name = self.repository.split("/")
        return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"

    @property
    def run_url(self) -> str:
        return f"{self.server_url}/{self.repository}/actions/runs/{self.run_id}/attempts/{self.run_attempt}"

    def comment_url(self, comment_id: int) -> str:
        return f"{self.server_url}/{self.repository}/pull/{self.pr_number}#issuecomment-{comment_id}"


def job_results(needs: Any) -> dict[str, str]:
    """`needs.<job>.result` from `toJSON(needs)`; a job that is not there is missing."""
    out: dict[str, str] = {}
    if isinstance(needs, Mapping):
        for job, value in needs.items():
            if isinstance(value, Mapping) and isinstance(value.get("result"), str):
                out[str(job)] = value["result"]
    return out


def dependency_review_outcome(needs: Any, env_value: str | None) -> str | None:
    """The exported dependency-review step outcome (spec "Reasons").

    Read from the job output in `needs` and from `DEPENDENCY_REVIEW_OUTCOME`.
    None (missing) when neither has it; when both have it and they differ,
    the result is not `success`.
    """
    values: list[str] = []
    job = needs.get(verdict.DEPENDENCY_REVIEW_JOB) if isinstance(needs, Mapping) else None
    outputs = job.get("outputs") if isinstance(job, Mapping) else None
    from_needs = outputs.get(DEPENDENCY_REVIEW_OUTPUT) if isinstance(outputs, Mapping) else None
    for v in (from_needs, env_value):
        if isinstance(v, str) and v:
            values.append(v)
    if not values:
        return None
    if len(set(values)) > 1:
        return "conflicting outcomes"
    return values[0]


def load_artifacts(
    data_dir: Path | str, digests: Mapping[str, str]
) -> tuple[verdict.ArtifactRead, tuple[verdict.ArtifactRead, ...]]:
    """The bundle and the three pass records from their fixed directories.

    A missing directory or an empty digest is an `ArtifactRead` error (the
    `artifact` reason, not waivable), never an exception (D10).
    """
    root = Path(data_dir)
    bundle = verdict.load_artifact(
        root / "bundle",
        kind="bundle",
        expected_name=collect.BUNDLE_FILE_NAME,
        expected_digest=digests.get("bundle", ""),
    )
    passes = tuple(
        verdict.load_artifact(
            root / envelope.pass_dir_name(name),
            kind="pass",
            expected_name=envelope.PASS_FILE_NAMES[name],
            expected_digest=digests.get(name, ""),
        )
        for name in verdict.PASS_NAMES
    )
    return bundle, passes


def bundle_snapshot(read: verdict.ArtifactRead) -> snapshot.Snapshot | None:
    doc = read.envelope
    if read.error is not None or doc is None:
        return None
    return snapshot.Snapshot(
        head_sha=doc["head_sha"],
        base_repository_id=doc["base_repository_id"],
        base_ref=doc["base_ref"],
        base_tip_sha=doc["base_tip_sha"],
        merge_base_sha=doc["merge_base_sha"],
    )


def _payload(read: verdict.ArtifactRead) -> Mapping[str, Any] | None:
    doc = read.envelope
    if read.error is not None or doc is None or doc["status"] not in verdict.BUNDLE_PAYLOAD_STATUSES:
        return None
    return doc["payload"]


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def bundle_files(read: verdict.ArtifactRead) -> tuple[verdict.FileSides, ...]:
    """Changed files and the PR title and body pseudo-files, for the citation check.

    The bundle is data: an entry with a bad shape is left out, which can only
    make a finding unverified (blocking never depends on verification).
    """
    payload = _payload(read)
    if payload is None:
        return ()
    out: list[verdict.FileSides] = []
    work = linediff.WorkBudget()  # one diff work budget for every file of the run
    files = payload.get("files")
    for entry in files if isinstance(files, list) else ():
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            continue
        f = verdict.changed_file(
            entry["path"],
            old_path=_opt_str(entry.get("old_path")),
            base_raw=_opt_str(entry.get("base_content")),
            head_raw=_opt_str(entry.get("head_content")),
            work=work,
        )
        if f.no_hunks_reason is not None:
            # The job log says why (repr: a path is one log line).
            print(f"publish: {f.path!r}: {f.no_hunks_reason}; its findings go to the summary", file=sys.stderr)
        out.append(f)
    pr = payload.get("pr")
    if isinstance(pr, Mapping):
        out.extend(verdict.metadata_files_from_raw(_opt_str(pr.get("title")), _opt_str(pr.get("body"))))
    return tuple(out)


# ---------------------------------------------------------------------------
# Reads: snapshot, override inputs, run list
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotRead:
    """One fresh snapshot check before a write.

    `revalidation` is `snapshot.revalidate` against the bundle snapshot, or
    None when there is no bundle snapshot. With no bundle, only the PR head is
    checked against the event head (`head_moved`), so the summary can still
    explain the failure (D10). `error` means the check could not run.
    """

    revalidation: snapshot.Revalidation | None
    error: str | None = None
    head_moved: bool = False

    @property
    def blocks_writes(self) -> bool:
        if self.error is not None or self.head_moved:
            return True
        return self.revalidation is not None and self.revalidation.stale

    def describe(self) -> str:
        if self.error is not None:
            return f"snapshot check failed: {self.error}"
        if self.head_moved:
            return f"stale: {snapshot.STALE_HEAD_SHA}"
        if self.revalidation is not None and self.revalidation.stale:
            return "stale: " + ", ".join(self.revalidation.stale_reasons)
        return "current"


def _read_pr(api: GitHubApi, ctx: PublishContext) -> Mapping[str, Any]:
    pr = api.get_json(f"{ctx.repo_path}/pulls/{ctx.pr_number}", max_bytes=collect.PR_MAX_BYTES)
    if not isinstance(pr, Mapping) or pr.get("number") != ctx.pr_number:
        raise collect.CollectError("PR response is not for the event's PR")
    base = pr.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if not isinstance(base_repo, Mapping) or base_repo.get("id") != ctx.repository_id:
        raise collect.CollectError("PR base repository is not the event repository")
    return pr


def check_snapshot(api: GitHubApi, ctx: PublishContext, snap: snapshot.Snapshot | None) -> SnapshotRead:
    """Read the PR, the current tip of its base ref and `tip...head`, then
    `snapshot.revalidate` (spec "Consistent snapshot", Re-validate)."""
    try:
        pr = _read_pr(api, ctx)
        if snap is None:
            head = pr.get("head")
            return SnapshotRead(None, head_moved=not isinstance(head, Mapping) or head.get("sha") != ctx.head_sha)
        base_ref = pr["base"].get("ref")
        if not isinstance(base_ref, str) or not base_ref:
            raise collect.CollectError("PR base ref is not a non-empty string")
        tip = collect._read_base_tip(api, ctx.repo_path, base_ref)
        compare = api.get_json(
            f"{ctx.repo_path}/compare/{tip}...{snap.head_sha}",
            params={"per_page": 1},
            max_bytes=collect.COMPARE_MAX_BYTES,
        )
        return SnapshotRead(snapshot.revalidate(snap, pr, tip, compare))
    except (collect.CollectError, snapshot.SnapshotError) as exc:
        return SnapshotRead(None, error=str(exc)[:300])


def _parse_comments(items: Sequence[Any]) -> tuple[verdict.Comment, ...]:
    """A comment with a bad shape is skipped: it can be neither an override
    nor the sticky summary."""
    out = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        try:
            out.append(verdict.Comment.from_api(item))
        except ValueError:
            continue
    return tuple(out)


def read_timeline(api: GitHubApi, ctx: PublishContext) -> verdict.Timeline:
    """Every page of the PR timeline. A page or parse error: `complete=False`."""
    try:
        items = api.get_pages(f"{ctx.repo_path}/issues/{ctx.pr_number}/timeline")
        events = []
        for item in items:
            if not isinstance(item, Mapping):
                raise ValueError("timeline item is not an object")
            events.append(verdict.TimelineEvent.from_api(item))
    except (collect.CollectError, ValueError):
        return verdict.Timeline((), False)
    return verdict.Timeline(tuple(events), True)


def read_permission(api: GitHubApi, ctx: PublishContext, login: str) -> str | None:
    """The legacy `permission` field now; None when it cannot be read."""
    if not _LOGIN_RE.fullmatch(login):
        return None
    try:
        doc = api.get_json(
            f"{ctx.repo_path}/collaborators/{urllib.parse.quote(login, safe='')}/permission",
            max_bytes=PERMISSION_MAX_BYTES,
        )
    except collect.CollectError:
        return None
    perm = doc.get("permission") if isinstance(doc, Mapping) else None
    return perm if isinstance(perm, str) else None


def read_override_inputs(
    api: GitHubApi, ctx: PublishContext, pair: verdict.SnapshotPair | None
) -> tuple[verdict.OverrideInputs, tuple[verdict.Comment, ...]]:
    """All issue comments and the full timeline, every page; then the
    permission of each author whose comment passes every check but the
    permission one (spec "Override", V16).

    Returns the inputs and the comments (for the sticky lookup). Comments that
    cannot be read give no override.
    """
    try:
        comments = _parse_comments(api.get_pages(f"{ctx.repo_path}/issues/{ctx.pr_number}/comments"))
    except collect.CollectError:
        comments = ()
    timeline = read_timeline(api, ctx)
    pure = verdict.OverrideInputs(comments, timeline, {}, ctx.pr_author)
    candidates = sorted(
        {
            c.author_login.lower(): c.author_login
            for c in verdict.evaluate_overrides(pure, pair)
            if c.rejection == verdict.OV_NO_PERMISSION
        }.values()
    )
    permissions = {login: read_permission(api, ctx, login) for login in candidates}
    return verdict.OverrideInputs(comments, timeline, permissions, ctx.pr_author), comments


def read_runs(api: GitHubApi, ctx: PublishContext, head_sha: str) -> verdict.RunList:
    """Runs of any workflow on the head SHA, every page (spec "Final check").
    A list read only in part, or a run with a bad id, makes `complete=False`."""
    try:
        items, total = api.get_wrapped_pages(
            f"{ctx.repo_path}/actions/runs", "workflow_runs", params={"head_sha": head_sha}
        )
    except collect.CollectError:
        return verdict.RunList((), False)
    complete = len(items) >= total
    runs = []
    for item in items:
        rid = item.get("id") if isinstance(item, Mapping) else None
        if isinstance(rid, bool) or not isinstance(rid, int):
            complete = False
            continue
        runs.append(verdict.RunRecord(rid, _opt_str(item.get("path"))))
    return verdict.RunList(tuple(runs), complete)


# ---------------------------------------------------------------------------
# Inline review
# ---------------------------------------------------------------------------

_FINDING_KEY_RE = re.compile(r"<!-- oc-finding:([0-9a-f]{64}) -->")
UNTRUSTED_NOTE = "Model output from untrusted input. Check it before you act on it."
VERIFIED_NOTE = "Verified means only that the quoted text is at that place. It does not mean the claim is true."


def finding_key(f: verdict.CitedFinding) -> str:
    """SHA-256 of `file\\0side\\0title\\0quote` (D14)."""
    raw = "\0".join((f.file, f.side, f.title, f.quote))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def read_posted_keys(api: GitHubApi, ctx: PublishContext) -> frozenset[str]:
    """Dedupe keys in the review comments of `github-actions[bot]` on the PR.
    A read error gives no keys, so findings are posted again, never hidden."""
    try:
        items = api.get_pages(f"{ctx.repo_path}/pulls/{ctx.pr_number}/comments")
    except collect.CollectError:
        return frozenset()
    keys: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        user, body = item.get("user"), item.get("body")
        if isinstance(user, Mapping) and user.get("login") == verdict.BOT_LOGIN and isinstance(body, str):
            keys.update(_FINDING_KEY_RE.findall(body))
    return frozenset(keys)


def _diff_path(f: verdict.CitedFinding, files: Sequence[verdict.FileSides]) -> str | None:
    """The path GitHub shows for the cited file (the new path of a rename)."""
    if f.side == "base":
        for fs in files:
            if fs.old_path == f.file:
                return fs.path
    for fs in files:
        if fs.path == f.file:
            return fs.path
    return None


def _finding_line(f: verdict.CitedFinding) -> str:
    """Severity, category and confidence are schema enums; the pass name is ours."""
    return f"**{f.severity} {f.category}**, confidence {f.confidence}, pass {f.pass_name}"


def inline_comment_body(f: verdict.CitedFinding, key: str) -> str:
    return "\n\n".join(
        (
            f"<!-- oc-finding:{key} -->",
            _finding_line(f),
            _esc("title", f.title),
            _esc("explanation", f.explanation),
            f"_{UNTRUSTED_NOTE}_",
        )
    )


@dataclass(frozen=True)
class InlineOutcome:
    """Keys posted by this run, keys already on the PR, and keys that this
    run could not post (they show in full in the summary, D7)."""

    posted: frozenset[str] = frozenset()
    earlier: frozenset[str] = frozenset()
    not_posted: frozenset[str] = frozenset()
    note: str | None = None


def build_review(
    result: verdict.GateResult,
    files: Sequence[verdict.FileSides],
    posted: frozenset[str],
    head_sha: str,
) -> tuple[dict[str, Any] | None, frozenset[str], frozenset[str]]:
    """The review request for verified, inline-eligible findings that are not
    on the PR yet. Returns (request or None, new keys, keys already posted)."""
    comments = []
    new: set[str] = set()
    earlier: set[str] = set()
    for f in result.findings:
        if not (f.verified and f.inline):
            continue
        key = finding_key(f)
        if key in posted:
            earlier.add(key)
            continue
        path = _diff_path(f, files)
        if key in new or path is None:
            continue
        new.add(key)
        comments.append(
            {
                "path": path,
                "line": f.line,
                "side": "RIGHT" if f.side == "head" else "LEFT",
                "body": inline_comment_body(f, key),
            }
        )
    if not comments:
        return None, frozenset(), frozenset(earlier)
    body = (
        f"OC Claude review, run {result.run_id}: {len(comments)} inline finding(s). "
        f"{UNTRUSTED_NOTE} The gate result is in the summary comment."
    )
    request = {"commit_id": head_sha, "event": REVIEW_EVENT, "body": body, "comments": comments}
    return request, frozenset(new), frozenset(earlier)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

# GitHub rejects a comment body over 65,536 characters (D8). The margin
# leaves room for the truncation notes.
SUMMARY_MAX_CHARS = 65_536
SUMMARY_LIMIT = 64_000
# The cut data is in the gate job log (`log_full_record`) and, under its cap,
# in the step summary.
TRUNCATED_NOTE = "truncated, see the run log"
OVERFLOW_NOTE = (
    "The summary does not fit in one comment, even after every permitted cut. "
    "Reasons, SHAs and override data are never cut, so this run fails closed."
)

# Cut order (D8): unverified findings, low and medium findings, dependency
# delta, signals. Every other block has no rank and is never cut: reasons,
# result, SHAs, override data, and also the blocks D8 does not list (high and
# critical findings, model summaries, hard block and coverage details).
CUT_UNVERIFIED = 0
CUT_LOW_MEDIUM = 1
CUT_DEPENDENCY = 2
CUT_SIGNALS = 3
CUT_ORDER = (CUT_UNVERIFIED, CUT_LOW_MEDIUM, CUT_DEPENDENCY, CUT_SIGNALS)


@dataclass
class _Block:
    text: str
    rank: int | None = None  # None: never cut
    group: str = ""


def _cut_note(n: int) -> str:
    return f"- {n} item(s) {TRUNCATED_NOTE}."


def _fit(blocks: Sequence[_Block], limit: int) -> tuple[str | None, bool]:
    """Join blocks; cut by rank in `CUT_ORDER`, from the end of each rank,
    until it fits. Each group that lost blocks gets one note where its first
    cut block was. The space left after the never-cut blocks is the budget of
    the cut ranks. Returns (None, True) when the never-cut blocks alone do not
    fit: the caller fails closed (D8)."""
    keep = [True] * len(blocks)
    cut: dict[str, int] = {}
    size = sum(len(b.text) + 1 for b in blocks) - 1  # joined with "\n"
    for rank in CUT_ORDER:
        for i in reversed(range(len(blocks))):
            if size <= limit:
                break
            b = blocks[i]
            if b.rank != rank:
                continue
            keep[i] = False
            n = cut.get(b.group, 0)
            size -= len(b.text) + 1
            size += len(_cut_note(n + 1)) + 1 - (len(_cut_note(n)) + 1 if n else 0)
            cut[b.group] = n + 1
    if size > limit:
        return None, True
    out: list[str] = []
    for b, k in zip(blocks, keep):
        if k:
            out.append(b.text)
        elif b.group in cut:
            out.append(_cut_note(cut.pop(b.group)))
    return "\n".join(out), not all(keep)


def _waivable(r: verdict.Reason) -> str:
    return "waivable by override" if r.waivable else "not waivable"


def _usage_numbers(meta: Mapping[str, Any]) -> dict[str, int]:
    usage = meta.get("usage")
    out: dict[str, int] = {}
    if isinstance(usage, Mapping):
        for k, v in usage.items():
            if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                out[k] = v
    return out


USAGE_FIELDS = (
    ("input_tokens", "input"),
    ("output_tokens", "output"),
    ("cache_creation_input_tokens", "cache write"),
    ("cache_read_input_tokens", "cache read"),
    ("iterations", "attempts"),
)


def _usage_text(nums: Mapping[str, int]) -> str:
    parts = [f"{label} {nums[k]}" for k, label in USAGE_FIELDS if k in nums]
    return ", ".join(parts) if parts else "no usage recorded"


def _finding_where(f: verdict.CitedFinding) -> str:
    return f"{_esc('file', f.file)} line {f.line} ({f.side})"


def _finding_block(f: verdict.CitedFinding, inline: InlineOutcome) -> _Block:
    key = finding_key(f)
    head = f"- {_finding_line(f)}, at {_finding_where(f)}: {_esc('title', f.title)}"
    rank = None if f.severity in verdict.BLOCKING_SEVERITIES else CUT_LOW_MEDIUM
    group = f"findings-{f.pass_name}"
    if not f.verified:
        return _Block(
            "\\\n  ".join(
                (
                    head,
                    f"Not verified: {_esc('reason', f.unverified_reason or 'unknown')}",
                    _esc("explanation", f.explanation),
                    f"Quote: {_esc('quote', f.quote)}",
                )
            ),
            CUT_UNVERIFIED,
            "unverified",
        )
    if key in inline.posted:
        return _Block(f"{head}. See the inline comment.", rank, group)
    if key in inline.earlier:
        return _Block(f"{head}. See the inline comment from an earlier run.", rank, group)
    if key in inline.not_posted:
        where = "Inline comment not posted, shown here."
    elif f.file in verdict.META_PATHS:
        where = "PR title or body, summary only."
    else:
        where = "Outside the diff, summary only."
    return _Block(
        "\\\n  ".join((head, where, _esc("explanation", f.explanation), f"Quote: {_esc('quote', f.quote)}")),
        rank,
        group,
    )


def _check_block(item: Any, rank: int | None, group: str) -> _Block | None:
    if not isinstance(item, Mapping):
        return None
    text = f"- {_esc('label', item.get('id'))}: {_esc('evidence', item.get('detail'))}"
    if item.get("file"):
        text += f", in {_esc('path', item.get('file'))}"
    if item.get("subject"):
        text += f", {_esc('evidence', item.get('subject'))}"
    lines = item.get("lines")
    if isinstance(lines, list) and lines:
        nums = [str(n) for n in lines[:10] if isinstance(n, int) and not isinstance(n, bool)]
        if nums:
            text += ", lines " + " ".join(nums) + (" and more" if len(lines) > 10 else "")
    return _Block(text, rank, group)


def _delta_blocks(delta: Any) -> list[_Block]:
    if not isinstance(delta, Mapping):
        return []
    out: list[_Block] = []
    for ch in delta.get("changes") or ():
        if not isinstance(ch, Mapping):
            continue
        old = ch.get("old_versions")
        olds = " ".join(_esc("version", v) for v in old) if isinstance(old, list) and old else "none"
        source = ch.get("source") if isinstance(ch.get("source"), Mapping) else {}
        text = (
            f"- {_esc('label', ch.get('ecosystem'))} {_esc('package_name', ch.get('name'))}: "
            f"{olds} to {_esc('version', ch.get('new_version'))}, "
            f"source {_esc('label', source.get('kind'))} {_esc('url', source.get('normalized'))}, "
            f"in {_esc('path', ch.get('path'))}"
        )
        reg = ch.get("registry")
        if isinstance(reg, Mapping):
            text += f", published {_esc('label', reg.get('published'))}"
            scripts = reg.get("install_scripts")
            if isinstance(scripts, Mapping) and scripts:
                text += ", install scripts " + " ".join(_esc("label", k) for k in sorted(map(str, scripts)))
        if ch.get("has_install_script") is True:
            text += ", has install script"
        out.append(_Block(text, CUT_DEPENDENCY, "dependency"))
    for s in delta.get("new_global_sources") or ():
        if isinstance(s, Mapping):
            src = s.get("source") if isinstance(s.get("source"), Mapping) else {}
            out.append(
                _Block(
                    f"- new file-wide source in {_esc('path', s.get('path'))}: {_esc('url', src.get('normalized'))}",
                    CUT_DEPENDENCY,
                    "dependency",
                )
            )
    for fl in delta.get("failures") or ():
        if isinstance(fl, Mapping):
            out.append(
                _Block(
                    f"- failed: {_esc('path', fl.get('path'))}: {_esc('reason', fl.get('reason'))}",
                    CUT_DEPENDENCY,
                    "dependency",
                )
            )
    return out


def _coverage_blocks(cov: Any) -> list[_Block]:
    if not isinstance(cov, Mapping):
        return [_Block("Coverage: no coverage record.")]
    complete = "complete" if cov.get("complete") is True else "NOT complete"
    nums = []
    for k, label in (("files_in_comparison", "files in comparison"), ("files_collected", "files collected")):
        v = cov.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            nums.append(f"{label} {v}")
    trees = cov.get("trees_complete")
    if isinstance(trees, bool):
        nums.append("trees complete" if trees else "trees NOT complete")
    out = [_Block(f"Coverage: {complete}" + (f" ({', '.join(nums)})." if nums else "."))]
    files = cov.get("files")
    for f in files if isinstance(files, list) else ():
        if isinstance(f, Mapping) and f.get("coverage") == "unavailable":
            out.append(
                _Block(
                    f"- unavailable: {_esc('path', f.get('path'))}: {_esc('reason', f.get('reason'))}",
                )
            )
    return out


@dataclass(frozen=True)
class RenderedSummary:
    """The sticky summary body. `cut`: D8 cuts were made (the full record goes
    to the run log). `overflow`: the never-cut data did not fit, so the body is
    the short fail-closed notice and the run must fail."""

    body: str
    cut: bool
    overflow: bool = False


def _header_lines(ctx: PublishContext, result: verdict.GateResult, status: str) -> list[str]:
    snap = result.snapshot
    if snap is not None:
        computed = (
            f"Computed for head SHA `{snap.head_sha}`, merge base `{snap.merge_base_sha}`, "
            f"base ref {_esc('ref', snap.base_ref)}."
        )
    else:
        computed = f"No valid bundle. Event head SHA `{ctx.head_sha}`, merge base unknown."
    return [
        verdict.STICKY_MARKER,
        f"## OC Claude review: {status}",
        f"Result for run [{ctx.run_id}]({ctx.run_url}), attempt {ctx.run_attempt}.",
        computed,
        "The result that counts is the required workflow in the merge box.",
    ]


def _overflow_body(ctx: PublishContext, result: verdict.GateResult) -> str:
    """The fail-closed notice when the never-cut data does not fit (D8). It
    has a fixed size: the result, the SHAs, a count per reason code and the
    override count. The full record is in the run log."""
    counts: dict[str, int] = {}
    for r in result.reasons:
        counts[r.code] = counts.get(r.code, 0) + 1
    lines = _header_lines(ctx, result, verdict.FAIL)
    lines += ["\n### Summary too large", OVERFLOW_NOTE]
    lines.append(
        f"The computed gate result was {result.status}. The full record (every reason, override, "
        "finding and prefilter result) is in the run log."
    )
    lines.append("\n### Reasons")
    if not counts:
        lines.append("No reason applies.")
    for code in sorted(counts):
        waivable = "waivable by override" if verdict.WAIVABLE[code] else "not waivable"
        lines.append(f"- {code} ({waivable}): {counts[code]} reason(s)")
    lines.append(f"\n### Override\n{len(result.valid_overrides)} valid override(s).")
    lines.append(f"\n[Workflow run]({ctx.run_url}). The result that counts is the required workflow in the merge box.")
    return "\n".join(lines)


def render_summary(
    ctx: PublishContext,
    result: verdict.GateResult,
    *,
    bundle: Mapping[str, Any] | None,
    inline: InlineOutcome,
    limit: int = SUMMARY_LIMIT,
) -> RenderedSummary:
    """The sticky summary body (D8). Every untrusted string goes through
    `escape_field`."""
    b: list[_Block] = [_Block(line) for line in _header_lines(ctx, result, result.status)]
    add = b.append

    add(_Block("\n### Reasons"))
    if not result.reasons:
        add(_Block("No reason applies."))
    for r in result.reasons:
        add(_Block(f"- {r.code} ({_waivable(r)}): {_esc('reason', r.detail)}"))

    if result.override_command is not None:
        add(_Block("\n### Override"))
        add(
            _Block(
                "The gate fails for waivable reasons only. A person with write access who is not "
                "the PR author can post this comment, with a reason, then re-run the newest run "
                "of the required workflow:\n\n```\n" + result.override_command + "\n```"
            )
        )
    valid = result.valid_overrides
    if valid:
        if result.override_command is None:
            add(_Block("\n### Override"))
        waived = ", ".join(r.code for r in result.waived) or "none"
        add(_Block(f"Override applied: {'yes' if result.override_applied else 'no'}. Waived reasons: {waived}."))
        for c in valid:
            add(
                _Block(
                    f"- by {_esc('login', c.author_login)} at {c.created_at.isoformat()}: "
                    f"{_esc('reason', c.reason)} ([comment]({ctx.comment_url(c.comment_id)}))"
                )
            )

    payload = None
    if bundle is not None and bundle.get("status") in verdict.BUNDLE_PAYLOAD_STATUSES:
        payload = bundle.get("payload")
    if isinstance(payload, Mapping):
        pre = payload.get("prefilter") if isinstance(payload.get("prefilter"), Mapping) else {}
        add(_Block("\n### Prefilter (code, no LLM)"))
        hard = [x for x in (_check_block(i, None, "hard-blocks") for i in pre.get("hard_blocks") or ()) if x]
        sig = [x for x in (_check_block(i, CUT_SIGNALS, "signals") for i in pre.get("signals") or ()) if x]
        add(_Block(f"Hard blocks: {len(hard)}."))
        b.extend(hard)
        add(_Block(f"Signals: {len(sig)}."))
        b.extend(sig)
        b.extend(_coverage_blocks(payload.get("coverage")))
        add(_Block("\n### Dependency delta"))
        delta = _delta_blocks(payload.get("dependency_delta"))
        b.extend(delta or [_Block("No dependency changes.")])

    add(_Block("\n### Findings per pass"))
    add(_Block(f"_{UNTRUSTED_NOTE} {VERIFIED_NOTE}_"))
    if inline.note:
        add(_Block(_esc("reason", inline.note)))
    by_pass = {p.name: p for p in result.passes}
    for name in verdict.PASS_NAMES:
        info = by_pass.get(name)
        if info is None:
            add(_Block(f"\n#### {name}: no valid pass record"))
            continue
        line = f"\n#### {name}: {info.status}"
        model = info.meta.get("model")
        if isinstance(model, str) and model:
            line += f", model {_esc('model', model)}"
        reason = info.meta.get("reason")
        if isinstance(reason, str) and reason:
            line += f", {_esc('reason', reason)}"
        add(_Block(line))
        if info.summary:
            add(_Block(f"Model summary: {_esc('summary', info.summary)}"))
        verified = [f for f in result.findings if f.pass_name == name and f.verified]
        if not verified:
            add(_Block("No verified findings."))
        for f in sorted(verified, key=lambda f: f.severity not in verdict.BLOCKING_SEVERITIES):
            b.append(_finding_block(f, inline))

    unverified = [f for f in result.findings if not f.verified]
    if unverified:
        add(_Block("\n### Unverified findings"))
        add(_Block(f"_The citation of these findings did not check out. {UNTRUSTED_NOTE}_"))
        b.extend(_finding_block(f, inline) for f in unverified)

    add(_Block("\n### Token usage"))
    totals: dict[str, int] = {}
    for info in result.passes:
        nums = _usage_numbers(info.meta)
        for k, v in nums.items():
            totals[k] = totals.get(k, 0) + v
        add(_Block(f"- {info.name}: {_usage_text(nums)}"))
    add(_Block(f"- total: {_usage_text(totals)}"))
    add(_Block(f"\n[Workflow run]({ctx.run_url}). The result that counts is the required workflow in the merge box."))
    body, cut = _fit(b, limit)
    if body is None:
        return RenderedSummary(_overflow_body(ctx, result), True, overflow=True)
    return RenderedSummary(body, cut)


def _step_summary_record(
    ctx: PublishContext, result: verdict.GateResult | None, codes: Sequence[str], publish_error: str | None = None
) -> str:
    """One JSON line: run, result, reason codes and token counts per pass (D6).
    Only integers and fixed names, so no fence escape is needed. A failed
    publication makes the result `fail` and adds `publish_error`. A stale
    run (`stale` in the codes) is `fail` too: stale is never waivable, and an
    early stale exit can hold a gate result computed before the run went stale."""
    passes: dict[str, Any] = {}
    for info in result.passes if result is not None else ():
        model = info.meta.get("model")
        passes[info.name] = {
            "status": info.status,
            "model": re.sub(r"[^A-Za-z0-9._:-]", "", model)[:100] if isinstance(model, str) else None,
            "usage": _usage_numbers(info.meta),
        }
    record: dict[str, Any] = {
        "run_id": ctx.run_id,
        "run_attempt": ctx.run_attempt,
        "result": verdict.FAIL if result is None or publish_error is not None or verdict.R_STALE in codes else result.status,
        "reasons": sorted(set(codes)),
        "passes": passes,
    }
    if publish_error is not None:
        record["publish_error"] = publish_error
    return json.dumps(record, ensure_ascii=True, separators=(",", ":"))


def _fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


# GitHub caps the step summary of one step at 1 MiB.
STEP_SUMMARY_FULL_MAX = 512 * 1024


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {k: _redact_strings(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_strings(v) for v in value]
    return value


def full_record(ctx: PublishContext, result: verdict.GateResult, bundle: Mapping[str, Any] | None) -> str:
    """Everything the summary shows, as JSON with credentials redacted: the
    reasons, the overrides, every finding, and the bundle's prefilter results,
    coverage and dependency delta. For the run log when the comment was cut (D8)."""
    payload = None
    if bundle is not None and bundle.get("status") in verdict.BUNDLE_PAYLOAD_STATUSES:
        payload = bundle.get("payload")
    payload = payload if isinstance(payload, Mapping) else {}
    snap = result.snapshot
    doc = {
        "run_id": ctx.run_id,
        "run_attempt": ctx.run_attempt,
        "result": result.status,
        "head_sha": snap.head_sha if snap is not None else ctx.head_sha,
        "merge_base_sha": snap.merge_base_sha if snap is not None else None,
        "base_ref": snap.base_ref if snap is not None else None,
        "reasons": [{"code": r.code, "waivable": r.waivable, "detail": r.detail} for r in result.reasons],
        "override_applied": result.override_applied,
        "waived": [r.code for r in result.waived],
        "overrides": [
            {
                "author": c.author_login,
                "created_at": c.created_at.isoformat(),
                "reason": c.reason,
                "comment_url": ctx.comment_url(c.comment_id),
            }
            for c in result.valid_overrides
        ],
        "findings": [
            {
                "pass": f.pass_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "file": f.file,
                "side": f.side,
                "line": f.line,
                "title": f.title,
                "explanation": f.explanation,
                "quote": f.quote,
                "verified": f.verified,
                "inline": f.inline,
                "unverified_reason": f.unverified_reason,
            }
            for f in result.findings
        ],
        "prefilter": payload.get("prefilter"),
        "coverage": payload.get("coverage"),
        "dependency_delta": payload.get("dependency_delta"),
    }
    return json.dumps(_redact_strings(doc), ensure_ascii=True, indent=1)


def log_full_record(text: str) -> None:
    """Print the full record to the gate job log: the "run log" that each cut
    note names. The record holds untrusted text, so workflow commands are
    stopped while it prints (`::stop-commands::` with a random token)."""
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}")
    print("oc-claude-review full record (the summary comment was cut):")
    print(text)
    print(f"::{token}::", flush=True)


def append_step_summary(
    path: Path | str | None,
    ctx: PublishContext,
    result: verdict.GateResult | None,
    *,
    codes: Sequence[str] = (),
    full: str | None = None,
    publish_error: str | None = None,
) -> None:
    """Append the JSON line (spec "Cost reporting": token counts, no currency),
    and the full record when the summary was cut and it fits under the cap."""
    if not path:
        return
    codes = list(codes) or ([r.code for r in result.reasons] if result is not None else [])
    parts = ["oc-claude-review record:", _fence(_step_summary_record(ctx, result, codes, publish_error))]
    if full is not None and len(full) <= STEP_SUMMARY_FULL_MAX:
        parts += ["Full record (the summary comment was cut):", _fence(full)]
    elif full is not None:
        parts.append("The summary comment was cut. The full record is over the step summary cap; it is in the gate job log.")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n\n".join(parts) + "\n")
    except OSError as exc:
        print(f"publish: cannot write the step summary: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Writes and the run
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SummaryWrite:
    """The result of one summary write. `comment_id` can be None after a
    successful POST whose response has no usable id."""

    ok: bool
    comment_id: int | None = None


def write_summary(
    api: GitHubApi,
    ctx: PublishContext,
    comments: Sequence[verdict.Comment],
    body: str,
    sticky_id: int | None = None,
) -> SummaryWrite:
    """PATCH the bot's sticky comment, or POST a new one. Never raises; a
    refused write gives `ok=False`."""
    if sticky_id is None:
        sticky = verdict.find_sticky_comment(comments)
        sticky_id = sticky.id if sticky is not None else None
    try:
        if sticky_id is not None:
            api.write("PATCH", f"{ctx.repo_path}/issues/comments/{sticky_id}", {"body": body})
            return SummaryWrite(True, sticky_id)
        doc = api.write("POST", f"{ctx.repo_path}/issues/{ctx.pr_number}/comments", {"body": body})
    except WriteError as exc:
        print(f"publish: summary write failed: {exc}", file=sys.stderr)
        return SummaryWrite(False)
    cid = doc.get("id")
    return SummaryWrite(True, cid if isinstance(cid, int) and not isinstance(cid, bool) else None)


def post_inline_review(
    api: GitHubApi,
    ctx: PublishContext,
    result: verdict.GateResult,
    files: Sequence[verdict.FileSides],
    head_sha: str,
    snap: snapshot.Snapshot | None,
) -> InlineOutcome | None:
    """Post one `COMMENT` review for the new inline findings. Returns None
    when the fresh snapshot check before the write shows the run stale."""
    if not any(f.verified and f.inline for f in result.findings):
        return InlineOutcome()
    request, new, earlier = build_review(result, files, read_posted_keys(api, ctx), head_sha)
    if request is None:
        return InlineOutcome(earlier=earlier)
    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()} before the inline review; no more writes", file=sys.stderr)
        return None
    try:
        api.write("POST", f"{ctx.repo_path}/pulls/{ctx.pr_number}/reviews", request)
    except WriteError as exc:
        # D7: one review per run. On 422 (a position GitHub's PR view does
        # not have) or any other failure, every finding of the request goes
        # to the summary. The gate does not change.
        if exc.status == 422:
            why = "GitHub rejected the inline review (HTTP 422)"
        else:
            why = "the inline review could not be posted"
        print(f"publish: {why}: {exc}", file=sys.stderr)
        return InlineOutcome(earlier=earlier, not_posted=new, note=f"{why}; its findings are shown in full here.")
    return InlineOutcome(posted=new, earlier=earlier)


def _artifact_stale(result: verdict.GateResult) -> bool:
    """A stale status in the bundle or a pass record (not the publisher's own
    missing re-check, which `SnapshotRead` covers)."""
    return any(r.code == verdict.R_STALE and r.detail != verdict.NOT_REVALIDATED for r in result.reasons)


def publish(
    api: GitHubApi,
    ctx: PublishContext,
    *,
    data_dir: Path | str,
    needs: Any,
    dependency_outcome_env: str | None,
    digests: Mapping[str, str],
    step_summary: Path | str | None = None,
) -> int:
    """The gate job. Returns the exit code: 0 only for `pass`."""
    bundle_read, pass_reads = load_artifacts(data_dir, digests)
    snap = bundle_snapshot(bundle_read)
    pair = verdict.SnapshotPair(snap.head_sha, snap.merge_base_sha, snap.base_ref) if snap else None
    head_sha = snap.head_sha if snap else ctx.head_sha

    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()}; nothing written", file=sys.stderr)
        append_step_summary(step_summary, ctx, None, codes=[verdict.R_STALE])
        return 1
    overrides, comments = read_override_inputs(api, ctx, pair)
    files = bundle_files(bundle_read)
    result = verdict.compute_gate(
        verdict.GateInputs(
            context=ctx.run_context,
            job_results=job_results(needs),
            dependency_review_outcome=dependency_review_outcome(needs, dependency_outcome_env),
            bundle=bundle_read,
            passes=pass_reads,
            revalidation=check.revalidation,
            prefilter=verdict.prefilter_evidence_from_bundle(bundle_read),
            files=files,
            overrides=overrides,
        )
    )
    if _artifact_stale(result):
        print("publish: the run is stale; nothing written", file=sys.stderr)
        append_step_summary(step_summary, ctx, result)
        return 1

    # a) inline review
    inline = post_inline_review(api, ctx, result, files, head_sha, snap)
    if inline is None:
        append_step_summary(step_summary, ctx, result, codes=[*result.codes, verdict.R_STALE])
        return 1

    # b) sticky summary
    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()} before the summary; no more writes", file=sys.stderr)
        append_step_summary(step_summary, ctx, result, codes=[*result.codes, verdict.R_STALE])
        return 1
    bundle_doc = bundle_read.envelope if bundle_read.error is None else None
    summary = render_summary(ctx, result, bundle=bundle_doc, inline=inline)
    full = full_record(ctx, result, bundle_doc) if summary.cut else None
    if full is not None:
        log_full_record(full)
    written = write_summary(api, ctx, comments, summary.body)
    # The summary must be published in full (spec acceptance: a refused
    # summary write leaves the run failed; D8: never-cut data that does not
    # fit fails closed). This is not a gate reason, so no override applies.
    publish_error = None
    if not written.ok:
        publish_error = "the summary write failed"
    elif summary.overflow:
        publish_error = "the summary is over the comment limit"

    # c) final check: snapshot, override authority and run list read again
    check = check_snapshot(api, ctx, snap)
    overrides, comments = read_override_inputs(api, ctx, pair)
    runs = read_runs(api, ctx, head_sha)
    final = verdict.final_check(result, revalidation=check.revalidation, overrides=overrides, runs=runs)
    if check.blocks_writes:
        print(f"publish: {check.describe()} at the final check; no sticky update", file=sys.stderr)
        append_step_summary(
            step_summary, ctx, final, codes=[*final.codes, verdict.R_STALE], full=full, publish_error=publish_error
        )
        return 1
    if result.passed and not final.passed:
        # Best effort: the exit code is non-zero whatever this write does. The
        # reads above can take many pages, so check the snapshot once more.
        summary = render_summary(ctx, final, bundle=bundle_doc, inline=inline)
        check = check_snapshot(api, ctx, snap)
        if check.blocks_writes:
            print(f"publish: {check.describe()} before the summary update; no more writes", file=sys.stderr)
            append_step_summary(
                step_summary, ctx, final, codes=[*final.codes, verdict.R_STALE], full=full, publish_error=publish_error
            )
            return 1
        if summary.cut:
            full = full_record(ctx, final, bundle_doc)
            log_full_record(full)
        updated = write_summary(api, ctx, comments, summary.body, written.comment_id)
        # The step summary carries the full record of the comment as it stands:
        # none when the final summary was not cut, the initial one when the
        # update failed.
        if not summary.cut and updated.ok:
            full = None

    # d) exit code
    append_step_summary(step_summary, ctx, final, full=full, publish_error=publish_error)
    print(f"publish: result {final.status}, reasons {', '.join(sorted(final.codes)) or 'none'}")
    if publish_error is not None:
        print(f"publish: {publish_error}; the run fails", file=sys.stderr)
        return 1
    return verdict.exit_code(final)


def main(argv: Sequence[str] | None = None, *, transport: collect.Transport | None = None) -> int:
    """Workflow entry (plan 2.3.3). Any unexpected error exits 1: the gate fails closed."""
    parser = argparse.ArgumentParser(description="Gate job: compute the gate and write the PR comments.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--needs-json", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        event = envelope.parse_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
        ctx = PublishContext.from_event(
            event,
            run_id=int(env["GITHUB_RUN_ID"]),
            run_attempt=int(env["GITHUB_RUN_ATTEMPT"]),
            server_url=env.get("GITHUB_SERVER_URL"),
        )
        try:
            needs = envelope.parse_json(Path(args.needs_json).read_bytes())
        except (OSError, envelope.EnvelopeError) as exc:
            print(f"publish: needs JSON unreadable ({exc}); every job counts as missing", file=sys.stderr)
            needs = {}
        api = GitHubApi(env["GITHUB_TOKEN"], transport or collect.default_transport)
        return publish(
            api,
            ctx,
            data_dir=args.data_dir,
            needs=needs,
            dependency_outcome_env=env.get("DEPENDENCY_REVIEW_OUTCOME"),
            digests={k: env.get(v, "") for k, v in DIGEST_ENV.items()},
            step_summary=env.get("GITHUB_STEP_SUMMARY"),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on any error
        print(f"publish failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
