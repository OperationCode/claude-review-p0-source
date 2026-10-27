"""GitHub REST reads -> bundle envelope (spec "Bundle (collected by code)",
"Consistent snapshot", "Coverage limits", "Dependency delta").

Collect reads the PR through the GitHub REST API only. It never checks out,
installs, builds or runs PR content. Every read is by SHA through the BASE
repo's git API, which also serves fork head objects (V18):

    PR metadata -> head SHA check against the event (stale) -> base tip
    -> merge base from compare `base_tip...head`, once
    -> recursive trees of merge base and head -> changed files in code
    -> blobs by SHA -> deps.py delta and registry lookups
    -> prefilter.py -> patches (render.redact_patch) -> size gate -> envelope

Rules this module keeps:

- One small HTTP client with an injectable transport. Every response has a
  byte cap that applies before parsing, a timeout, at most 2 retries (429, 5xx
  and network errors only) and no redirects. It talks to api.github.com only.
- A truncated tree or a blob that cannot be read is never skipped: the
  prefilter turns it into the hard block "incomplete coverage".
- The bundle carries `head_content` and `base_content` (raw blob text of each
  text side) for the citation check in verdict.py only; render never sends
  them to Claude. Claude gets the head text in `content`, for text files under
  2,000 lines, and every changed line in the patch.
- A `skipped-size` bundle keeps the prefilter result, the coverage record and
  the dependency delta (K-7). The producer digest is the SHA-256 of the exact
  envelope file bytes (K-5).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oc_review import deps, envelope, linediff, prefilter, render
from oc_review.snapshot import (
    MODE_SUBMODULE,
    MODE_SYMLINK,
    ChangedFile,
    SnapshotError,
    StaleSnapshot,
    TreeDiff,
    capture_snapshot,
    diff_trees,
    merge_base_from_compare,
)

API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
ACCEPT_JSON = "application/vnd.github+json"
ACCEPT_RAW = "application/vnd.github.raw+json"

# Byte caps per response, applied before parsing.
PR_MAX_BYTES = 2 * 1024 * 1024
REF_MAX_BYTES = 64 * 1024
# The compare response lists changed files with patches; only the merge base is read.
COMPARE_MAX_BYTES = 32 * 1024 * 1024
TREE_MAX_BYTES = 16 * 1024 * 1024
PAGE_MAX_BYTES = 8 * 1024 * 1024
MAX_PAGES = 50

TIMEOUT_SECONDS = 30.0
RETRIES = 2
# Blob reads per run. The job token has a small hourly request budget per
# repo; past this cap a blob counts as unreadable (coverage `unavailable`).
MAX_BLOB_READS = 500

# Registry lookups per run (ruling R-LOOKUPS, K-11). A large lockfile, or a
# migration whose base counts as empty (K-10), can need thousands of
# lookups; done one by one they outlast the 10-minute job timeout, and the
# run fails with no bundle and no reason. Lookups go to the two fixed
# registry hosts only, at most this many at once.
REGISTRY_LOOKUP_CONCURRENCY = 8
# Wall-clock budget for all lookups of a run, well under the job timeout so
# collect still writes the bundle. A key with no result by then fails.
REGISTRY_LOOKUP_BUDGET_SECONDS = 240.0
# Unique keys looked up per run; past the cap a key fails without a lookup.
MAX_REGISTRY_LOOKUPS = 3000
# Fixed failure reasons ("incomplete dependency data"), in the order a file
# with several picks its one reason.
LOOKUP_BUDGET_EXCEEDED = "registry lookup failed: lookup time budget exceeded"
LOOKUP_COUNT_CAP = "registry lookup failed: over the lookup count cap"
LOOKUP_FAILED = "registry lookup failed"
_LOOKUP_REASON_ORDER = (LOOKUP_BUDGET_EXCEEDED, LOOKUP_COUNT_CAP, LOOKUP_FAILED)

SIZE_GATE_TOKENS = 150_000
CHARS_PER_TOKEN = 4
SIZE_ESTIMATE_ROUNDS = 10
SIZE_GATE_REASON = "too large for automatic review"

SCHEMA_VERSION = 1
BUNDLE_FILE_NAME = "bundle.json"

# Unified diff context lines, as git.
PATCH_CONTEXT = 3
# Past this product of middle lengths, or past the work budget of the file or
# of the run (linediff), the patch is one hunk that removes every base line and
# adds every head line between the common prefix and suffix: a larger patch
# than git's, never a wrong one.
PATCH_DIFF_BUDGET = linediff.DIFF_BUDGET
NO_NEWLINE = "\\ No newline at end of file"

# Signal added by collect (spec "Consistent snapshot"): GitHub's PR view can
# use an older merge base than the reviewed comparison.
CHANGED_FILES_DIFFER = "changed-files-differ"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
# RFC 8288 link-value pieces: `<uri>`, then `; name=value` parameters, where a
# value is a token or a quoted string.
_LINK_URI_RE = re.compile(r"[ \t]*<([^<>]*)>")
_LINK_PARAM_RE = re.compile(
    r'[ \t]*;[ \t]*([!#$%&\'*+.^_`|~0-9A-Za-z-]+)[ \t]*(?:=[ \t]*(?:"((?:[^"\\]|\\.)*)"|([^\s;,"]+)))?'
)
_LINK_SEP_RE = re.compile(r"[ \t]*(,|\Z)")


class CollectError(Exception):
    """Collect cannot build a trustworthy bundle. The job fails, so the gate fails."""


class HttpError(CollectError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ResponseTooLarge(HttpError):
    """A response body is over its byte cap."""


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    max_bytes: int
    timeout: float
    # Request body (JSON bytes) for the publisher's writes; None for a GET.
    body: bytes | None = None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    # The URL that served the body.
    url: str
    # Header names in lower case.
    headers: Mapping[str, str] = field(default_factory=dict)


# transport(request) -> HttpResponse. It reads at most `max_bytes + 1` body
# bytes, never follows a redirect, and raises OSError or TimeoutError on a
# network failure. Unit tests inject a transport that replays recorded
# responses.
Transport = Callable[[HttpRequest], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


def default_transport(
    request: HttpRequest, *, opener: Any = None, clock: Callable[[], float] = time.monotonic
) -> HttpResponse:
    """urllib transport for api.github.com. `timeout` bounds each socket
    operation and the whole read."""
    parts = urllib.parse.urlsplit(request.url)
    if parts.scheme != "https" or parts.hostname != API_HOST or parts.port is not None:
        raise HttpError("default_transport refuses a URL outside api.github.com")
    opener = opener or urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        request.url, data=request.body, method=request.method, headers=dict(request.headers)
    )
    deadline = clock() + request.timeout
    try:
        with opener.open(req, timeout=request.timeout) as resp:
            chunks: list[bytes] = []
            size = 0
            while size <= request.max_bytes:
                if clock() > deadline:
                    raise TimeoutError(f"{request.url}: over the {request.timeout}s deadline")
                chunk = resp.read(min(65536, request.max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return HttpResponse(resp.status, b"".join(chunks), resp.url, headers)
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return HttpResponse(exc.code, b"", request.url, headers)


class GitHubClient:
    """GET-only client for the GitHub REST API on api.github.com."""

    def __init__(
        self,
        token: str,
        transport: Transport = default_transport,
        *,
        timeout: float = TIMEOUT_SECONDS,
        retries: int = RETRIES,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._transport = transport
        self._timeout = timeout
        self._retries = retries
        self._sleep = sleep

    def _url(self, path: str, params: Mapping[str, Any] | None) -> str:
        if not path.startswith("/") or "//" in path or "/../" in path or path.endswith("/.."):
            raise HttpError(f"bad API path {path[:200]!r}")
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        return f"https://{API_HOST}{path}{query}"

    def _get(self, url: str, *, accept: str, max_bytes: int) -> HttpResponse:
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "oc-claude-review",
            "X-GitHub-Api-Version": API_VERSION,
        }
        request = HttpRequest("GET", url, headers, max_bytes, self._timeout)
        last = ""
        for attempt in range(self._retries + 1):
            if attempt:
                self._sleep(0.5 * 2 ** (attempt - 1))
            try:
                resp = self._transport(request)
            except OSError as exc:  # TimeoutError is an OSError
                last = f"{type(exc).__name__}: {exc}"
                continue
            if resp.status == 429 or resp.status >= 500:
                last = f"HTTP {resp.status}"
                continue
            served = urllib.parse.urlsplit(resp.url)
            if served.scheme != "https" or served.hostname != API_HOST or served.port is not None:
                raise HttpError(f"{url}: response came from another host")
            if resp.status != 200:
                raise HttpError(f"{url}: HTTP {resp.status}", resp.status)
            if len(resp.body) > max_bytes:
                raise ResponseTooLarge(f"{url}: response is over the {max_bytes} byte cap", resp.status)
            return resp
        raise HttpError(f"{url}: failed after {self._retries + 1} attempts ({last})")

    def get_json(self, path: str, *, max_bytes: int, params: Mapping[str, Any] | None = None) -> Any:
        resp = self._get(self._url(path, params), accept=ACCEPT_JSON, max_bytes=max_bytes)
        return _parse_json(resp.body, path)

    def get_raw(self, path: str, *, max_bytes: int) -> bytes:
        return self._get(self._url(path, None), accept=ACCEPT_RAW, max_bytes=max_bytes).body

    def get_pages(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_bytes: int = PAGE_MAX_BYTES,
        max_pages: int = MAX_PAGES,
    ) -> list[Any]:
        """Every item of a paginated list endpoint, following `Link: rel="next"`.

        Each page must be a JSON array. A Link header that does not parse, more
        than one next link, a next link to another host, or more than
        `max_pages` pages fails: a list that was not read completely is never
        returned as complete.
        """
        url = self._url(path, {"per_page": 100, **(params or {})})
        items: list[Any] = []
        for _ in range(max_pages):
            resp = self._get(url, accept=ACCEPT_JSON, max_bytes=max_bytes)
            page = _parse_json(resp.body, path)
            if not isinstance(page, list):
                raise HttpError(f"{path}: page is not a list")
            items.extend(page)
            link = resp.headers.get("link")
            if link is None:
                return items
            try:
                nexts = [uri for uri, rels in parse_link_header(link) if "next" in rels]
            except ValueError as exc:
                raise HttpError(f"{path}: {exc}") from exc
            if not nexts:
                return items
            if len(nexts) > 1:
                raise HttpError(f"{path}: more than one next page link")
            url = nexts[0]
            nxt = urllib.parse.urlsplit(url)
            if nxt.scheme != "https" or nxt.hostname != API_HOST or nxt.port is not None:
                raise HttpError(f"{path}: next page link points to another host")
        raise HttpError(f"{path}: more than {max_pages} pages")


def parse_link_header(value: str) -> list[tuple[str, frozenset[str]]]:
    """(URI, relation types) for each link-value of a `Link` header (RFC 8288).

    Relation types are lower case; `rel` takes its first occurrence. Raises
    ValueError when the header does not parse, so a caller never mistakes a
    malformed header for the last page.
    """
    out: list[tuple[str, frozenset[str]]] = []
    pos = 0
    while True:
        m = _LINK_URI_RE.match(value, pos)
        if m is None:
            raise ValueError("Link header does not parse")
        uri, pos = m.group(1), m.end()
        rel: str | None = None
        while (p := _LINK_PARAM_RE.match(value, pos)) is not None:
            pos = p.end()
            if p.group(1).lower() == "rel" and rel is None:
                quoted, token = p.group(2), p.group(3)
                rel = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else token or ""
        sep = _LINK_SEP_RE.match(value, pos)
        if sep is None:
            raise ValueError("Link header does not parse")
        out.append((uri, frozenset((rel or "").lower().split())))
        if not sep.group(1):
            return out
        pos = sep.end()


def _parse_json(body: bytes, what: str) -> Any:
    try:
        return envelope.parse_json(body)
    except envelope.EnvelopeError as exc:
        raise HttpError(f"{what}: {exc}") from exc


# ---------------------------------------------------------------------------
# Trusted run context
# ---------------------------------------------------------------------------


def _require_sha(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.match(value):
        raise CollectError(f"{what} is not a 40-character lowercase hex SHA")
    return value


def _require_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CollectError(f"{what} is not a positive integer")
    return value


@dataclass(frozen=True)
class EventContext:
    """What collect takes from the trusted `pull_request_target` event payload."""

    repository: str  # owner/name of the base repo
    repository_id: int
    pr_number: int
    head_sha: str

    @classmethod
    def from_event(cls, event: Mapping[str, Any]) -> EventContext:
        try:
            repo = event["repository"]
            pr = event["pull_request"]
            full_name, repo_id = repo["full_name"], repo["id"]
            number, head_sha = pr["number"], pr["head"]["sha"]
        except (KeyError, TypeError) as exc:
            raise CollectError(f"event payload is missing {exc}") from exc
        if not isinstance(full_name, str) or not _REPO_RE.match(full_name):
            raise CollectError("event repository full_name is not owner/name")
        return cls(
            repository=full_name,
            repository_id=_require_int(repo_id, "event repository id"),
            pr_number=_require_int(number, "event PR number"),
            head_sha=_require_sha(head_sha, "event head SHA"),
        )


# ---------------------------------------------------------------------------
# Unified diff of two blobs
# ---------------------------------------------------------------------------


def _git_lines(text: str | None) -> tuple[list[str], bool]:
    """Lines split on LF (git line numbers), and whether the last line has no LF."""
    if not text:
        return [], False
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
        return lines, False
    return lines, True


def _opcodes(a: Sequence[Any], b: Sequence[Any], work: linediff.WorkBudget | None) -> linediff.Diff:
    return linediff.diff(a, b, PATCH_DIFF_BUDGET, work)


def _range(start: int, stop: int) -> str:
    length = stop - start
    if length == 1:
        return str(start + 1)
    return f"{start if length == 0 else start + 1},{length}"


def unified_diff(
    base_text: str | None, head_text: str | None, work: linediff.WorkBudget | None = None
) -> tuple[str, int, int]:
    """Unified diff of two blob texts: (patch, additions, deletions).

    Hunks only, no file header. A last line with no LF gets the marker
    `\\ No newline at end of file`, and counts as a different line from the
    same text with an LF. Every patch line equals its blob line, as
    `render.redact_patch` requires. `work` is the run's diff work budget.
    """
    return _patch(base_text, head_text, work)[:3]


def _patch(
    base_text: str | None, head_text: str | None, work: linediff.WorkBudget | None
) -> tuple[str, int, int, str | None]:
    """`unified_diff`, and why the patch is coarse (None: it is exact)."""
    a, a_noeol = _git_lines(base_text)
    b, b_noeol = _git_lines(head_text)
    a_keys: list[Any] = list(a)
    b_keys: list[Any] = list(b)
    if a_noeol:
        a_keys[-1] = (a[-1], "no-eol")
    if b_noeol:
        b_keys[-1] = (b[-1], "no-eol")
    out: list[str] = []
    adds = dels = 0
    no_eol = NO_NEWLINE
    diff = _opcodes(a_keys, b_keys, work)
    for group in linediff.hunks(diff.codes, PATCH_CONTEXT):
        out.append(f"@@ -{_range(group[0][1], group[-1][2])} +{_range(group[0][3], group[-1][4])} @@")
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for i in range(i1, i2):
                    out.append(" " + a[i])
                    if a_noeol and i == len(a) - 1:
                        out.append(no_eol)
                continue
            for i in range(i1, i2):
                out.append("-" + a[i])
                dels += 1
                if a_noeol and i == len(a) - 1:
                    out.append(no_eol)
            for j in range(j1, j2):
                out.append("+" + b[j])
                adds += 1
                if b_noeol and j == len(b) - 1:
                    out.append(no_eol)
    return "".join(line + "\n" for line in out), adds, dels, diff.reason


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Tree:
    response: Mapping[str, Any]
    # Blob SHA -> size from the tree entry, when the entry has one.
    sizes: Mapping[str, int]
    # Every blob and submodule path.
    paths: frozenset[str]


def _repo_path(event: EventContext) -> str:
    owner, name = event.repository.split("/")
    return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"


def _read_tree(client: GitHubClient, repo: str, sha: str) -> _Tree:
    doc = client.get_json(f"{repo}/git/trees/{sha}", params={"recursive": "1"}, max_bytes=TREE_MAX_BYTES)
    if not isinstance(doc, Mapping) or not isinstance(doc.get("tree"), list):
        raise CollectError("tree response has no entry list")
    sizes: dict[str, int] = {}
    paths: set[str] = set()
    for item in doc["tree"]:
        if not isinstance(item, Mapping):
            continue  # diff_trees rejects it
        kind, path, size = item.get("type"), item.get("path"), item.get("size")
        if kind in ("blob", "commit") and isinstance(path, str):
            paths.add(path)
        if kind == "blob" and isinstance(item.get("sha"), str) and isinstance(size, int) and not isinstance(size, bool):
            sizes[item["sha"]] = size
    return _Tree(doc, sizes, frozenset(paths))


def _read_base_tip(client: GitHubClient, repo: str, base_ref: str) -> str:
    if base_ref.startswith("/") or ".." in base_ref or "//" in base_ref:
        raise CollectError("base ref is not a valid branch name")
    doc = client.get_json(
        f"{repo}/git/ref/heads/{urllib.parse.quote(base_ref, safe='/')}", max_bytes=REF_MAX_BYTES
    )
    if not isinstance(doc, Mapping) or doc.get("ref") != f"refs/heads/{base_ref}":
        raise CollectError("ref response is not for the base ref")
    obj = doc.get("object")
    if not isinstance(obj, Mapping) or obj.get("type") != "commit":
        raise CollectError("base ref does not point to a commit")
    return _require_sha(obj.get("sha"), "base tip SHA")


def _blob_shas(diff: TreeDiff) -> list[str]:
    """SHA of every blob side to read, in path order; a gitlink side has no blob."""
    out: list[str] = []
    for c in diff.files:
        if c.base_sha is not None and c.base_mode != MODE_SUBMODULE:
            out.append(c.base_sha)
        if c.head_sha is not None and c.head_mode != MODE_SUBMODULE:
            out.append(c.head_sha)
    return out


def _read_blobs(
    client: GitHubClient,
    repo: str,
    shas: Iterable[str],
    sizes: Mapping[str, int],
    *,
    max_blob_bytes: int,
    max_reads: int,
) -> tuple[dict[str, bytes | None], dict[str, str]]:
    """Blob bytes by SHA (None when a blob cannot be read), and the coverage
    reason `over-cap` by SHA for a blob that is None because of its size.

    A blob whose tree entry is over the cap is not fetched. Past `max_reads`
    a blob counts as unreadable. The prefilter checks every blob against its
    SHA before it scans it.
    """
    out: dict[str, bytes | None] = {}
    reasons: dict[str, str] = {}
    reads = 0
    for sha in shas:
        if sha in out:
            continue
        if sizes.get(sha, 0) > max_blob_bytes:
            out[sha], reasons[sha] = None, "over-cap"
            continue
        if reads >= max_reads:
            out[sha] = None
            continue
        reads += 1
        try:
            out[sha] = client.get_raw(f"{repo}/git/blobs/{sha}", max_bytes=max_blob_bytes)
        except ResponseTooLarge:
            out[sha], reasons[sha] = None, "over-cap"
        except HttpError:
            out[sha] = None
    return out, reasons


# ---------------------------------------------------------------------------
# Dependency facts
# ---------------------------------------------------------------------------


def _parse_side(path: str, mode: str | None, data: bytes | None) -> deps.ParsedDeps:
    if mode == MODE_SYMLINK:
        raise deps.DepsError("symlink is not parsed")
    if data is None:
        raise deps.DepsError("blob not available")
    return deps.parse_file(path, data)


def _failure_reason(exc: deps.DepsError) -> str:
    """A fixed reason: a DepsError message can quote PR content."""
    if isinstance(exc, deps.UnsupportedVersionError):
        return "unknown lockfile version"
    if str(exc) in ("symlink is not parsed", "blob not available"):
        return str(exc)
    return "does not parse"


class _LastUrlCache:
    """Remembers the last successful registry response, so several versions
    of one package fetch its packument once (one group's lookups run in
    version order on one thread)."""

    def __init__(self, fetch: deps.Fetcher) -> None:
        self._fetch = fetch
        self._last: tuple[str, deps.FetchResult] | None = None

    def __call__(self, url: str, max_bytes: int, timeout: float) -> deps.FetchResult:
        if self._last is not None and self._last[0] == url:
            return self._last[1]
        result = self._fetch(url, max_bytes, timeout)
        self._last = (url, result) if result.status == 200 else None
        return result


RegistryKey = tuple[str, str, str]


class _BudgetSpent(deps.RegistryError):
    """No time is left in the run's lookup budget for a fetch or a retry."""


_LOOKUP_WAIT_SLICE_SECONDS = 0.05


def lookup_registry(
    keys: Iterable[RegistryKey],
    *,
    fetch: deps.Fetcher = deps.default_fetch,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    budget_seconds: float = REGISTRY_LOOKUP_BUDGET_SECONDS,
    concurrency: int = REGISTRY_LOOKUP_CONCURRENCY,
    max_lookups: int = MAX_REGISTRY_LOOKUPS,
) -> tuple[dict[RegistryKey, deps.RegistryInfo], dict[RegistryKey, str]]:
    """Registry data by key, and a fixed failure reason by key for every key
    that has no data (ruling R-LOOKUPS, K-11).

    Keys are deduplicated and sorted before any lookup starts. Keys past
    `max_lookups` are not looked up. The versions of one package run in
    order on one worker, so its packument is fetched once; at most
    `concurrency` packages run at once. Every lookup must finish within
    `budget_seconds` of the start: a fetch never gets more time than is left,
    no lookup, fetch or retry starts after the deadline, and a result that
    completes at or after the deadline is not taken. A key with no result at
    the deadline fails. Any error in a lookup fails that key only.

    Collect does not wait for a lookup past the deadline. The workers are
    daemon threads, so a hung lookup also does not hold the process open
    after collect writes the bundle.
    """
    unique = sorted(set(keys))
    failed = {key: LOOKUP_COUNT_CAP for key in unique[max_lookups:]}
    groups: dict[tuple[str, str], list[RegistryKey]] = {}
    for key in unique[:max_lookups]:
        groups.setdefault(key[:2], []).append(key)
    deadline = clock() + budget_seconds
    queue = list(groups.values())
    queue.reverse()  # workers pop from the end, so groups start in key order
    state = threading.Condition()
    results: dict[RegistryKey, deps.RegistryInfo | str] = {}
    finished = 0  # groups whose worker is done with them
    closed = False  # set at the deadline or when all groups finish

    def remaining() -> float:
        return deadline - clock()

    def bounded_fetch(url: str, max_bytes: int, timeout: float) -> deps.FetchResult:
        left = remaining()
        if left <= 0:
            raise _BudgetSpent("lookup time budget exceeded")
        return fetch(url, max_bytes, min(timeout, left))

    def bounded_sleep(seconds: float) -> None:
        if seconds >= remaining():
            raise _BudgetSpent("lookup time budget exceeded")
        sleep(seconds)

    def commit(key: RegistryKey, result: deps.RegistryInfo | str) -> bool:
        """Records a result that completed before the deadline; False when
        the lookups are over."""
        with state:
            if closed:
                return False
            if remaining() <= 0:
                results[key] = LOOKUP_BUDGET_EXCEEDED
                return False
            results[key] = result
            return True

    def run_group(group: list[RegistryKey]) -> None:
        cached = _LastUrlCache(bounded_fetch)
        for key in group:
            if remaining() <= 0:
                return  # the key has no result at the deadline
            ecosystem, name, version = key
            lookup = deps.lookup_npm if ecosystem == "npm" else deps.lookup_pypi
            result: deps.RegistryInfo | str
            try:
                result = lookup(name, version, cached, sleep=bounded_sleep)
            except _BudgetSpent:
                result = LOOKUP_BUDGET_EXCEEDED
            except Exception:  # noqa: BLE001 - any error is a failed lookup, never a lost bundle
                result = LOOKUP_FAILED
            if not commit(key, result):
                return

    def worker() -> None:
        nonlocal finished
        while True:
            with state:
                if closed or not queue or remaining() <= 0:
                    return
                group = queue.pop()
            try:
                run_group(group)
            finally:
                with state:
                    finished += 1
                    state.notify_all()

    for i in range(min(max(1, concurrency), len(groups))):
        threading.Thread(target=worker, name=f"registry-lookup-{i}", daemon=True).start()
    with state:
        # A short wait slice, so a clock that is not wall time (tests) still
        # ends the wait at its deadline.
        while finished < len(groups) and (left := remaining()) > 0:
            state.wait(min(left, _LOOKUP_WAIT_SLICE_SECONDS))
        closed = True
        expired = remaining() <= 0
        final = dict(results)
    registry: dict[RegistryKey, deps.RegistryInfo] = {}
    for group in groups.values():
        for key in group:
            found = final.get(key)
            if isinstance(found, deps.RegistryInfo):
                registry[key] = found
            elif found is not None:
                failed[key] = found
            else:
                failed[key] = LOOKUP_BUDGET_EXCEEDED if expired else LOOKUP_FAILED
    return registry, failed


def dependency_facts(
    diff: TreeDiff,
    blobs: Mapping[str, bytes | None],
    *,
    fetch: deps.Fetcher = deps.default_fetch,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    budget_seconds: float = REGISTRY_LOOKUP_BUDGET_SECONDS,
    concurrency: int = REGISTRY_LOOKUP_CONCURRENCY,
    max_lookups: int = MAX_REGISTRY_LOOKUPS,
) -> prefilter.DependencyFacts:
    """Parse each changed supported file at the merge base and the head, and
    look up every new exact registry version (`prefilter.registry_key`).

    A head side that does not parse is a `DepFailure`: the hard block
    "incomplete dependency data". A base side that does not parse or has an
    unknown version (ruling R-BASEDEPS, K-10), a deleted file too, counts as
    empty: every head entry is new and gets every check, and the base failure
    is only a signal (`base_failures`). A base blob that was not read is still
    a `DepFailure`. A file gets at most one `DepFailure`. A base symlink or
    gitlink holds no dependency data, so it counts as absent with no failure.
    A rename to another dependency family ignores the base, so the base is
    not parsed. A key with no registry data (`lookup_registry`: failed, over
    the count cap or past the time budget) is a `DepFailure` for its file.
    """
    parsed: set[str] = set()
    changes: list[deps.PackageChange] = []
    new_sources: list[deps.SourceIssue] = []
    failures: list[prefilter.DepFailure] = []
    base_failures: list[prefilter.DepFailure] = []
    for c in diff.files:
        family = deps.family_for_path(c.path)
        base_path = c.old_path or c.path
        base_family = deps.family_for_path(base_path)
        new: deps.ParsedDeps | None = None
        head_failed = False
        if family is not None and c.head_sha is not None and c.head_mode != MODE_SUBMODULE:
            try:
                new = _parse_side(c.path, c.head_mode, blobs.get(c.head_sha))
            except deps.DepsError as exc:
                failures.append(prefilter.DepFailure(c.path, _failure_reason(exc)))
                head_failed = True
            else:
                parsed.add(c.path)
        old: deps.ParsedDeps | None = None
        # A base of another family counts as absent; a rename to a path that
        # is not a dependency file is a delete.
        base_ignored = family is not None and base_family != family
        if (
            base_family is not None
            and not base_ignored
            and c.base_sha is not None
            and c.base_mode not in (MODE_SUBMODULE, MODE_SYMLINK)
        ):
            try:
                old = _parse_side(base_path, c.base_mode, blobs.get(c.base_sha))
            except deps.DepsError as exc:
                failure = prefilter.DepFailure(c.path, f"{_failure_reason(exc)} at the merge base")
                if str(exc) != "blob not available":
                    base_failures.append(failure)
                elif not head_failed:
                    failures.append(failure)
        if new is None:
            continue
        changes.extend(deps.compute_delta(old, new))
        old_sources = {s.normalized for s in old.global_sources} if old is not None else set()
        new_sources.extend(
            deps.SourceIssue(c.path, None, None, s) for s in new.global_sources if s.normalized not in old_sources
        )

    registry, failed_keys = lookup_registry(
        (k for ch in changes if (k := prefilter.registry_key(ch)) is not None),
        fetch=fetch,
        sleep=sleep,
        clock=clock,
        budget_seconds=budget_seconds,
        concurrency=concurrency,
        max_lookups=max_lookups,
    )
    # One fixed reason per file, the run-limit reason first; the delta shows
    # which entries have no registry data.
    reasons: dict[str, set[str]] = {}
    for ch in changes:
        key = prefilter.registry_key(ch)
        if key is not None and key in failed_keys:
            reasons.setdefault(ch.path, set()).add(failed_keys[key])
    for path in sorted(reasons):
        reason = next(r for r in _LOOKUP_REASON_ORDER if r in reasons[path])
        failures.append(prefilter.DepFailure(path, reason))
    return prefilter.DependencyFacts(
        parsed_paths=frozenset(parsed),
        changes=tuple(changes),
        new_global_sources=tuple(new_sources),
        registry=registry,
        failures=tuple(failures),
        base_failures=tuple(base_failures),
    )


def _delta_payload(facts: prefilter.DependencyFacts) -> dict[str, Any]:
    def info(ch: deps.PackageChange) -> dict[str, Any] | None:
        key = prefilter.registry_key(ch)
        found = facts.registry.get(key) if key is not None else None
        if found is None:
            return None
        return {
            "published": found.published.isoformat(),
            "install_scripts": dict(found.install_scripts),
            "has_wheel": found.has_wheel,
        }

    return {
        "changes": [
            {
                "path": ch.path,
                "ecosystem": ch.ecosystem,
                "name": ch.name,
                "old_versions": list(ch.old_versions),
                "new_version": ch.new_version,
                "source": asdict(ch.source),
                "direct": ch.direct,
                "has_install_script": ch.has_install_script,
                "registry": info(ch),
            }
            for ch in facts.changes
        ],
        "new_global_sources": [{"path": s.path, "source": asdict(s.source)} for s in facts.new_global_sources],
        "failures": [asdict(f) for f in facts.failures],
    }


# ---------------------------------------------------------------------------
# Bundle payload
# ---------------------------------------------------------------------------


def _pr_payload(pr: Mapping[str, Any], event: EventContext) -> dict[str, Any]:
    user = pr.get("user")
    labels = pr.get("labels")
    title, body = pr.get("title"), pr.get("body")
    if not isinstance(title, str) or not (body is None or isinstance(body, str)):
        raise CollectError("PR title or body is not a string")
    return {
        "repository": event.repository,
        "repository_id": event.repository_id,
        "number": event.pr_number,
        "title": title,
        "body": body or "",
        "author_login": user.get("login") if isinstance(user, Mapping) else None,
        "author_association": pr.get("author_association"),
        "labels": [lb["name"] for lb in labels if isinstance(lb, Mapping) and isinstance(lb.get("name"), str)]
        if isinstance(labels, list)
        else [],
        "changed_files": pr.get("changed_files"),
    }


def _file_entry(
    change: ChangedFile,
    cov: prefilter.FileCoverage,
    blobs: Mapping[str, bytes | None],
    sizes: Mapping[str, int],
    max_blob_bytes: int,
    work: linediff.WorkBudget,
) -> dict[str, Any]:
    def scan(sha: str | None, mode: str | None, path: str) -> prefilter.BlobScan | None:
        if sha is None or mode == MODE_SUBMODULE:
            return None
        return prefilter.scan_blob(blobs.get(sha), sha=sha, cap=max_blob_bytes, path=path)

    base = scan(change.base_sha, change.base_mode, change.old_path or change.path)
    head = scan(change.head_sha, change.head_mode, change.path)
    entry: dict[str, Any] = {
        "path": change.path,
        "old_path": change.old_path,
        "status": change.status,
        "base_mode": change.base_mode,
        "head_mode": change.head_mode,
        "additions": 0,
        "deletions": 0,
        "base_blob_sha": change.base_sha,
        "head_blob_sha": change.head_sha,
        "binary": False,
        "size": sizes.get(change.head_sha or "", sizes.get(change.base_sha or "")),
        "coverage": cov.coverage,
    }
    if cov.reason is not None:
        entry["coverage_reason"] = cov.reason
    if change.is_submodule:
        entry["submodule"] = True
    if change.is_symlink:
        entry["symlink"] = True
    if cov.coverage == "unavailable":
        return entry
    base_text = base.text if base is not None and base.kind == "full" else None
    head_text = head.text if head is not None and head.kind == "full" else None
    if base_text is None and head_text is None:
        # Binary blobs or gitlinks only: listed with size and SHA.
        entry["binary"] = cov.coverage == "binary"
        return entry
    # Each text side counts on its own. Opposite a gitlink or a binary blob,
    # the patch adds every head line or removes every base line, so a type
    # change never hides text from Claude or from the citation check.
    patch, adds, dels, coarse = _patch(base_text, head_text, work)
    if coarse is not None:
        # The job log says why (repr: a path is one log line).
        print(f"collect: {change.path!r}: {coarse}; the patch is one hunk for the changed middle", file=sys.stderr)
    try:
        entry["patch"] = render.redact_patch(patch, base_text, head_text)
    except render.RenderError as exc:
        raise CollectError(f"patch redaction failed: {exc}") from exc
    entry["patch_redaction"] = render.PATCH_REDACTION
    entry["additions"], entry["deletions"] = adds, dels
    if head_text is not None:
        if len(_git_lines(head_text)[0]) < render.MAX_HEAD_CONTENT_LINES:
            entry["content"] = head_text
        entry["head_content"] = head_text
    if base_text is not None:
        entry["base_content"] = base_text
    return entry


def _changed_files_signal(pr: Mapping[str, Any], diff: TreeDiff) -> dict[str, Any] | None:
    shown = pr.get("changed_files")
    if not diff.complete or not isinstance(shown, int) or isinstance(shown, bool) or shown == len(diff.files):
        return None
    check = prefilter.Check(
        id=CHANGED_FILES_DIFFER,
        level=prefilter.SIGNAL,
        detail=f"GitHub's PR view lists {shown} changed files; the reviewed comparison has {len(diff.files)}",
    )
    return {**asdict(check), "lines": list(check.lines)}


def estimate_tokens(bundle_envelope: Mapping[str, Any]) -> int:
    """Estimated input tokens of what Claude sees: rendered characters / 4."""
    try:
        text = render.render_bundle(bundle_envelope).text
    except render.RenderError as exc:
        raise CollectError(f"bundle does not render: {exc}") from exc
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def encode_envelope(doc: Mapping[str, Any]) -> bytes:
    """Envelope file bytes: compact UTF-8 JSON. Text that has a lone
    surrogate cannot be UTF-8, so such a document is written as ASCII JSON."""
    try:
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(doc, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Collected:
    envelope: dict[str, Any]
    data: bytes  # the envelope file bytes
    digest: str  # SHA-256 of `data`, hex: the producer digest (K-5)


def _finish(doc: dict[str, Any]) -> Collected:
    envelope.validate_envelope(doc)
    data = encode_envelope(doc)
    return Collected(doc, data, envelope.sha256_hex(data))


def collect(
    client: GitHubClient,
    event: EventContext,
    *,
    run_id: int,
    run_attempt: int,
    now: datetime,
    registry_fetch: deps.Fetcher = deps.default_fetch,
    registry_sleep: Callable[[float], None] = time.sleep,
    registry_clock: Callable[[], float] = time.monotonic,
    max_blob_bytes: int = prefilter.MAX_BLOB_BYTES,
    max_blob_reads: int = MAX_BLOB_READS,
    size_gate_tokens: int = SIZE_GATE_TOKENS,
    max_envelope_bytes: int = envelope.MAX_BYTES_BY_KIND["bundle"],
) -> Collected:
    """Read one PR through the API and build its bundle envelope.

    Returns status `stale` when the PR head is not the event head, `ok` when
    the bundle fits the size gate, else `skipped-size`. Raises CollectError
    when a read fails or a response has an unexpected shape.
    """
    repo = _repo_path(event)
    pr = client.get_json(f"{repo}/pulls/{event.pr_number}", max_bytes=PR_MAX_BYTES)
    if not isinstance(pr, Mapping) or pr.get("number") != event.pr_number:
        raise CollectError("PR response is not for the event's PR")
    base = pr.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if not isinstance(base_repo, Mapping) or base_repo.get("id") != event.repository_id:
        raise CollectError("PR base repository is not the event repository")
    base_ref = base.get("ref")  # type: ignore[union-attr]
    if not isinstance(base_ref, str) or not base_ref:
        raise CollectError("PR base ref is not a non-empty string")

    base_tip = _read_base_tip(client, repo, base_ref)
    # The compare runs once, for the event head. When the PR head is the
    # event head (not stale) this is `base_tip...head` as the spec says; when
    # it is not, the stale envelope still names a consistent pair.
    compare = client.get_json(
        f"{repo}/compare/{base_tip}...{event.head_sha}", params={"per_page": 1}, max_bytes=COMPARE_MAX_BYTES
    )
    context = {
        "schema_version": SCHEMA_VERSION,
        "kind": "bundle",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "repository_id": event.repository_id,
        "pr_number": event.pr_number,
    }
    try:
        snap = capture_snapshot(pr, base_tip, compare, event.head_sha)
    except StaleSnapshot:
        try:
            merge_base = merge_base_from_compare(compare, base_tip)
        except SnapshotError as exc:
            raise CollectError(f"compare response: {exc}") from exc
        return _finish({
            **context,
            "head_sha": event.head_sha,
            "base_repository_id": event.repository_id,
            "base_ref": base_ref,
            "base_tip_sha": base_tip,
            "merge_base_sha": merge_base,
            "status": "stale",
            "payload": None,
        })
    except SnapshotError as exc:
        raise CollectError(f"snapshot: {exc}") from exc
    context.update(
        head_sha=snap.head_sha,
        base_repository_id=snap.base_repository_id,
        base_ref=snap.base_ref,
        base_tip_sha=snap.base_tip_sha,
        merge_base_sha=snap.merge_base_sha,
    )

    base_tree = _read_tree(client, repo, snap.merge_base_sha)
    head_tree = _read_tree(client, repo, snap.head_sha)
    try:
        diff = diff_trees(base_tree.response, head_tree.response)
    except SnapshotError as exc:
        raise CollectError(f"tree: {exc}") from exc
    if not diff.complete:
        # A partial tree gives a wrong file list. The comparison is
        # incomplete; the prefilter records the hard block.
        diff = TreeDiff((), False)
    sizes = {**base_tree.sizes, **head_tree.sizes}
    blobs, unread_reasons = _read_blobs(
        client, repo, _blob_shas(diff), sizes,
        max_blob_bytes=max_blob_bytes, max_reads=max_blob_reads,
    )

    facts = dependency_facts(diff, blobs, fetch=registry_fetch, sleep=registry_sleep, clock=registry_clock)
    pr_meta = _pr_payload(pr, event)
    result = prefilter.run_prefilter(
        diff,
        blobs,
        head_paths=head_tree.paths,
        now=now,
        dependencies=facts,
        author_association=pr_meta["author_association"] if isinstance(pr_meta["author_association"], str) else None,
        pr_title=pr_meta["title"],
        pr_body=pr_meta["body"],
        max_blob_bytes=max_blob_bytes,
        unread_reasons=unread_reasons,
    )
    checks = result.to_dict()
    extra = _changed_files_signal(pr, diff)
    if extra is not None:
        checks["prefilter"]["signals"].append(extra)
    delta = _delta_payload(facts)
    work = linediff.WorkBudget()  # one diff work budget for every file of the run
    files = [
        _file_entry(c, cov, blobs, sizes, max_blob_bytes, work)
        for c, cov in zip(diff.files, result.coverage.files, strict=True)
    ]

    payload = {"pr": pr_meta, "files": files, "dependency_delta": delta, **checks}
    doc = {**context, "status": "ok", "payload": payload}
    size: dict[str, Any] = {"estimated_tokens": 0, "limit_tokens": size_gate_tokens}
    payload["size"] = size
    # The estimate is of the final rendered document, its own size field
    # included. The count can only grow with its digits, so this reaches its
    # fixed point in a few renders.
    for _ in range(SIZE_ESTIMATE_ROUNDS):
        tokens = estimate_tokens(doc)
        if tokens == size["estimated_tokens"]:
            break
        size["estimated_tokens"] = tokens
    else:
        raise CollectError("size estimate does not settle")
    reason = None
    if tokens > size_gate_tokens:
        reason = f"{SIZE_GATE_REASON}: estimated {tokens} tokens, limit {size_gate_tokens}"
    else:
        ok = _finish(doc)
        if len(ok.data) <= max_envelope_bytes:
            return ok
        reason = f"{SIZE_GATE_REASON}: bundle is {len(ok.data)} bytes, cap {max_envelope_bytes}"
    size["reason"] = reason
    skipped = _finish({
        **context,
        "status": "skipped-size",
        "payload": {"prefilter": checks["prefilter"], "coverage": checks["coverage"], "dependency_delta": delta, "size": size},
    })
    if len(skipped.data) > max_envelope_bytes:
        raise CollectError(f"skipped-size bundle is over the {max_envelope_bytes} byte cap")
    return skipped


def write_bundle(collected: Collected, directory: Path | str) -> Path:
    """Write the envelope file alone in `directory` (one file per artifact)."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    path = d / BUNDLE_FILE_NAME
    path.write_bytes(collected.data)
    return path


def main(argv: Sequence[str] | None = None) -> int:
    """Workflow entry: read the trusted event, write the bundle and job outputs.

    Outputs: `bundle-digest` (SHA-256 of the file bytes), `status`,
    `head-sha` and `merge-base-sha` (for the dependency-review job).
    """
    parser = argparse.ArgumentParser(description="Collect the PR bundle envelope.")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    try:
        event = EventContext.from_event(
            envelope.parse_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
        )
        client = GitHubClient(os.environ["GITHUB_TOKEN"])
        collected = collect(
            client,
            event,
            run_id=int(os.environ["GITHUB_RUN_ID"]),
            run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
            now=datetime.now(UTC),
        )
    except (CollectError, envelope.EnvelopeError, KeyError, ValueError, OSError) as exc:
        print(f"collect failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    write_bundle(collected, args.out_dir)
    doc = collected.envelope
    outputs = {
        "bundle-digest": collected.digest,
        "status": doc["status"],
        "head-sha": doc["head_sha"],
        "merge-base-sha": doc["merge_base_sha"],
    }
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
        fh.writelines(f"{k}={v}\n" for k, v in outputs.items())
    print(f"collect: status {doc['status']}, digest {collected.digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
