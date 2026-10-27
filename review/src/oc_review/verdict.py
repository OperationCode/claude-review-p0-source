"""Citation check, gate reasons, override checks and the gate result.

Every function takes data that the publisher already read (no I/O here,
except `load_artifact`, which wraps `envelope.read_artifact`). Artifacts,
comments, timeline events and findings are untrusted. Only code lowers risk:
model output can add reasons, never remove one, and an override can waive
only the reasons that `WAIVABLE` marks waivable.

Reason details and finding fields can hold untrusted text (paths, quotes).
The publisher escapes them before it posts anything.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from oc_review import envelope, linediff, render

PASS = "pass"
FAIL = "fail"

PASS_NAMES = ("review", "security", "supply-chain")
REQUIRED_JOBS = ("collect", "analyze", "dependency-review")
DEPENDENCY_REVIEW_JOB = "dependency-review"

# Reason codes, one per row of the spec's reasons table ("Gate", "Reasons").
R_JOB_RESULT = "job-result"
R_ARTIFACT = "artifact"
R_PASS_RECORDS = "pass-records"
R_STALE = "stale"
R_SUPERSEDED = "superseded"
R_BASE_NOT_DEFAULT = "base-not-default-branch"
R_HARD_BLOCK = "prefilter-hard-block"
R_DEPENDENCY_REVIEW = "dependency-review"
R_SIZE_GATE = "size-gate"
R_BLOCKING_FINDING = "blocking-finding"

# Code decides what an override can waive, never the caller.
WAIVABLE: Mapping[str, bool] = MappingProxyType(
    {
        R_JOB_RESULT: False,
        R_ARTIFACT: False,
        R_PASS_RECORDS: False,
        R_STALE: False,
        R_SUPERSEDED: False,
        R_BASE_NOT_DEFAULT: False,
        R_HARD_BLOCK: False,
        R_DEPENDENCY_REVIEW: False,
        R_SIZE_GATE: True,
        R_BLOCKING_FINDING: True,
    }
)

# Finding limit per pass (spec "Claude passes"). A pass over its limit is
# invalid (not waivable); its findings are still reported.
PASS_MAX_FINDINGS: Mapping[str, int] = MappingProxyType(
    {"review": 10, "security": 10, "supply-chain": 15}
)

# Bundle statuses that carry a payload with the prefilter result, coverage and
# dependency data (K-7). Only an `ok` bundle has content for Claude.
BUNDLE_PAYLOAD_STATUSES = frozenset({"ok", "skipped-size"})

# Completeness state of the prefilter evidence.
PREFILTER_COMPLETE = "complete"
PREFILTER_UNAVAILABLE = "unavailable"

BLOCKING_CATEGORIES = frozenset({"security", "supply-chain", "malicious", "prompt-injection"})
BLOCKING_SEVERITIES = frozenset({"high", "critical"})

# A quote must sit within this many lines of the cited line.
QUOTE_WINDOW = 3

# PR title and body are cited as pseudo-files on side `head` (ruling R-META).
# A leading `/` is never a git tree path, so no repo file can collide. They are
# never inline-eligible.
META_TITLE_PATH = "/.pr/title"
META_BODY_PATH = "/.pr/body"
META_PATHS = frozenset({META_TITLE_PATH, META_BODY_PATH})

# A quote that is only a redaction marker verifies only when the cited line holds
# that marker and no other text (ruling R-REDACT).
_REDACTION_MARKER_RE = re.compile(r"\[REDACTED:[^\[\]\s]+\]")
# Context lines around a change when hunks are computed from two texts.
HUNK_CONTEXT = 3

# Timeline events that move the push epoch (spec "Override", K-12). V16 showed
# a branch reset while the PR is closed leaves only "reopened"; change only
# this constant.
PUSH_EPOCH_EVENTS = frozenset(
    {
        "head_ref_force_pushed",
        "head_ref_deleted",
        "head_ref_restored",
        "base_ref_changed",
        "reopened",
    }
)

OVERRIDE_PREFIX = "/oc-review"
_OVERRIDE_RE = re.compile(r"/oc-review override (\S+) (\S+)(?: (.*))?")
_SHA_RE = re.compile(r"[0-9a-f]{40}")
# Legacy `permission` field of the collaborator permission API: maintain reads as write.
OVERRIDE_PERMISSIONS = frozenset({"admin", "write"})

# Detail of the `stale` reason when the publisher had no snapshot to re-check
# (for example, no valid bundle). It fails the gate like any stale reason.
NOT_REVALIDATED = "snapshot not re-validated"

BOT_LOGIN = "github-actions[bot]"
STICKY_MARKER = "<!-- oc-claude-review -->"
WORKFLOW_PATH = ".github/workflows/claude-review.yml"

# Override rejection codes, in the order they are checked.
OV_BOT_AUTHOR = "bot-author"
OV_MALFORMED = "malformed"
OV_EMPTY_REASON = "empty-reason"
OV_NO_SNAPSHOT = "no-snapshot"
OV_WRONG_HEAD = "wrong-head-sha"
OV_WRONG_MERGE_BASE = "wrong-merge-base-sha"
OV_TIMELINE_INCOMPLETE = "timeline-incomplete"
OV_BEFORE_EPOCH = "not-after-push-epoch"
OV_EDITED = "edited"
OV_PR_AUTHOR = "pr-author"
OV_NO_PERMISSION = "no-write-permission"


# ---------------------------------------------------------------- inputs


@dataclass(frozen=True)
class RunContext:
    """Trusted values from the event payload and the runner, never from an artifact."""

    repository_id: int
    pr_number: int
    run_id: int
    run_attempt: int


@dataclass(frozen=True)
class ArtifactRead:
    """One downloaded artifact: the validated envelope, or why it was rejected."""

    envelope: Mapping[str, Any] | None = None
    error: str | None = None


def load_artifact(
    directory: Path | str, *, kind: str, expected_name: str, expected_digest: str
) -> ArtifactRead:
    try:
        doc = envelope.read_artifact(
            directory, kind=kind, expected_name=expected_name, expected_digest=expected_digest
        )
    except envelope.EnvelopeError as exc:
        return ArtifactRead(error=str(exc))
    return ArtifactRead(envelope=doc)


class SnapshotCheck(Protocol):
    """The publisher's re-validation (`snapshot.Revalidation` fits)."""

    @property
    def stale_reasons(self) -> tuple[str, ...]: ...

    @property
    def base_not_default_branch(self) -> bool: ...


@dataclass(frozen=True)
class FileSides:
    """One changed file as the citation check sees it.

    `path` is the head path (the only path for a removed file). Text is the
    redacted text the model saw, or None when that side has no blob or its
    content is not available. Hunks are inclusive 1-based line ranges inside a
    diff hunk on that side. `no_hunks_reason` says why a file has no hunks
    because its line diff went past a budget (`linediff`).
    """

    path: str
    old_path: str | None = None
    base_text: str | None = None
    head_text: str | None = None
    base_hunks: tuple[tuple[int, int], ...] = ()
    head_hunks: tuple[tuple[int, int], ...] = ()
    no_hunks_reason: str | None = None


def metadata_files(title_text: str | None, body_text: str | None) -> tuple[FileSides, ...]:
    """Pseudo-files for the rendered (redacted) PR title and body, head side, no hunks."""
    return (
        FileSides(META_TITLE_PATH, head_text=title_text),
        FileSides(META_BODY_PATH, head_text=body_text),
    )


def _model(text: str | None) -> str | None:
    return None if text is None else render.model_text(text)


def changed_file(
    path: str,
    *,
    old_path: str | None = None,
    base_raw: str | None = None,
    head_raw: str | None = None,
    work: linediff.WorkBudget | None = None,
) -> FileSides:
    """One changed file from its raw blob texts (None: no blob or not available).

    Each side is the text the model saw (`render.model_text`). Hunks come from
    the raw texts; redaction keeps the line count (ruling R-LINES). `work` is
    the run's diff work budget.
    """
    base_hunks, head_hunks, reason = _hunks(base_raw, head_raw, HUNK_CONTEXT, work)
    return FileSides(path, old_path, _model(base_raw), _model(head_raw), base_hunks, head_hunks, reason)


def metadata_files_from_raw(title: str | None, body: str | None) -> tuple[FileSides, ...]:
    """`metadata_files` for the raw PR title and body, as the model saw them."""
    return metadata_files(_model(title), _model(body))


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    t = datetime.fromisoformat(value)
    if t.tzinfo is None:
        raise ValueError("timestamp has no time zone")
    return t


@dataclass(frozen=True)
class Comment:
    id: int
    author_login: str
    author_type: str
    body: str
    created_at: datetime
    updated_at: datetime
    html_url: str = ""

    @classmethod
    def from_api(cls, item: Mapping[str, Any]) -> Comment:
        """From one issue comment of the REST API. Raises ValueError on a bad shape."""
        user = item.get("user")
        if not isinstance(user, Mapping) or not isinstance(user.get("login"), str):
            raise ValueError("comment has no author")
        cid = item.get("id")
        if isinstance(cid, bool) or not isinstance(cid, int):
            raise ValueError("comment id is not an integer")
        body = item.get("body") or ""
        if not isinstance(body, str):
            raise ValueError("comment body is not a string")
        return cls(
            id=cid,
            author_login=user["login"],
            author_type=str(user.get("type") or ""),
            body=body,
            created_at=_parse_time(item.get("created_at")),
            updated_at=_parse_time(item.get("updated_at")),
            html_url=str(item.get("html_url") or ""),
        )


@dataclass(frozen=True)
class TimelineEvent:
    event: str
    created_at: datetime | None

    @classmethod
    def from_api(cls, item: Mapping[str, Any]) -> TimelineEvent:
        """Some timeline items (for example `committed`) have no `created_at`."""
        event = item.get("event")
        if not isinstance(event, str):
            raise ValueError("timeline item has no event name")
        raw = item.get("created_at")
        return cls(event=event, created_at=None if raw is None else _parse_time(raw))


@dataclass(frozen=True)
class Timeline:
    """`complete` is False unless every page was read and parsed."""

    events: tuple[TimelineEvent, ...]
    complete: bool


@dataclass(frozen=True)
class OverrideInputs:
    """Read again immediately before the gate and again at the final check."""

    comments: tuple[Comment, ...]
    timeline: Timeline
    permissions: Mapping[str, str | None]  # login -> legacy permission now; None if unread
    pr_author: str  # from the event payload
    bot_login: str = BOT_LOGIN


@dataclass(frozen=True)
class RunRecord:
    id: int
    path: str | None


@dataclass(frozen=True)
class RunList:
    """Runs of any workflow on the head SHA. `complete` is False unless every page was read."""

    runs: tuple[RunRecord, ...]
    complete: bool


@dataclass(frozen=True)
class PrefilterEvidence:
    """The prefilter result for one comparison pair, from a checked source.

    `state` is `PREFILTER_COMPLETE` only when the prefilter ran over the whole
    comparison of `head_sha` and `merge_base_sha`; any other value fails
    closed. Hard blocks are labels for the summary: the gate never reads risk
    or waivability from them.
    """

    state: str
    head_sha: str | None
    merge_base_sha: str | None
    hard_blocks: tuple[str, ...] = ()
    detail: str = ""

    @classmethod
    def unavailable(cls, detail: str) -> PrefilterEvidence:
        return cls(PREFILTER_UNAVAILABLE, None, None, (), detail)


def _hard_block_label(item: Mapping[str, Any]) -> str:
    label = str(item["id"])
    file = item.get("file")
    return f"{label} in {file}" if isinstance(file, str) and file else label


def _bundle_hard_blocks(bundle: Mapping[str, Any]) -> tuple[str, ...]:
    """Hard block labels of a schema-valid bundle; empty when it has no payload.

    Defense in depth: a coverage record whose `complete` is not exactly true
    is a hard block too, even when the prefilter list holds no
    `incomplete-coverage` entry.
    """
    if bundle["status"] not in BUNDLE_PAYLOAD_STATUSES:
        return ()
    payload = bundle["payload"]
    labels = [_hard_block_label(b) for b in payload["prefilter"]["hard_blocks"]]
    if payload["coverage"].get("complete") is not True:
        labels.append("incomplete-coverage (coverage record is not complete)")
    return tuple(labels)


def prefilter_evidence_from_bundle(read: ArtifactRead) -> PrefilterEvidence:
    """Prefilter evidence from the bundle payload (statuses `ok` and
    `skipped-size`), bound to the bundle's comparison pair. Any other bundle
    gives `unavailable`."""
    if read.error is not None or read.envelope is None:
        return PrefilterEvidence.unavailable(f"bundle: {read.error or 'no envelope'}")
    doc = read.envelope
    try:
        envelope.validate_envelope(doc)
    except envelope.EnvelopeError as exc:
        return PrefilterEvidence.unavailable(f"bundle: {exc}")
    if doc["kind"] != "bundle":
        return PrefilterEvidence.unavailable(f"bundle: kind {doc['kind']}")
    if doc["status"] not in BUNDLE_PAYLOAD_STATUSES:
        return PrefilterEvidence.unavailable(f"bundle status {doc['status']}")
    return PrefilterEvidence(
        PREFILTER_COMPLETE, doc["head_sha"], doc["merge_base_sha"], _bundle_hard_blocks(doc)
    )


@dataclass(frozen=True)
class GateInputs:
    context: RunContext
    job_results: Mapping[str, str]  # needs.<job>.result
    dependency_review_outcome: str | None  # exported step outcome; None if missing
    bundle: ArtifactRead
    passes: Sequence[ArtifactRead]
    revalidation: SnapshotCheck | None  # None: the publisher could not re-validate
    prefilter: PrefilterEvidence | None  # None: no prefilter evidence
    files: Sequence[FileSides]  # changed files of the reviewed comparison
    overrides: OverrideInputs


# ---------------------------------------------------------------- results


@dataclass(frozen=True)
class Reason:
    code: str
    detail: str

    @property
    def waivable(self) -> bool:
        return WAIVABLE[self.code]


@dataclass(frozen=True)
class SnapshotPair:
    head_sha: str
    merge_base_sha: str
    base_ref: str


@dataclass(frozen=True)
class CitedFinding:
    pass_name: str
    category: str
    severity: str
    confidence: str
    file: str
    side: str
    line: int
    quote: str
    title: str
    explanation: str
    verified: bool
    inline: bool
    blocking: bool
    unverified_reason: str | None


@dataclass(frozen=True)
class OverrideCandidate:
    comment_id: int
    author_login: str
    html_url: str
    created_at: datetime
    reason: str
    rejection: str | None  # None means valid

    @property
    def valid(self) -> bool:
        return self.rejection is None


@dataclass(frozen=True)
class PassInfo:
    """One schema-valid pass record, for the summary only.

    `meta` is a read-only copy of the envelope `meta` (empty when absent):
    the failure reason, model, stop reason and token usage. The gate never
    reads risk from it.
    """

    name: str
    status: str
    summary: str | None
    meta: Mapping[str, Any]


@dataclass(frozen=True)
class GateResult:
    status: str  # PASS | FAIL
    run_id: int
    reasons: tuple[Reason, ...]
    findings: tuple[CitedFinding, ...]
    snapshot: SnapshotPair | None
    overrides: tuple[OverrideCandidate, ...]
    override_applied: bool
    passes: tuple[PassInfo, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status == PASS

    @property
    def exit_code(self) -> int:
        return exit_code(self)

    @property
    def stale(self) -> bool:
        """A stale run writes nothing more (no sticky update, no removals)."""
        return any(r.code == R_STALE for r in self.reasons)

    @property
    def codes(self) -> frozenset[str]:
        return frozenset(r.code for r in self.reasons)

    @property
    def waivable_only(self) -> bool:
        return bool(self.reasons) and all(r.waivable for r in self.reasons)

    @property
    def valid_overrides(self) -> tuple[OverrideCandidate, ...]:
        return tuple(c for c in self.overrides if c.valid)

    @property
    def waived(self) -> tuple[Reason, ...]:
        return self.reasons if self.override_applied else ()

    @property
    def override_command(self) -> str | None:
        """The line the summary prints, only when the gate fails for waivable reasons only."""
        if self.passed or not self.waivable_only or self.snapshot is None:
            return None
        return (
            f"{OVERRIDE_PREFIX} override {self.snapshot.head_sha} "
            f"{self.snapshot.merge_base_sha} <reason>"
        )


def exit_code(result: GateResult) -> int:
    """0 only for `pass`."""
    return 0 if result.status == PASS else 1


# ---------------------------------------------------------------- citations


def _lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _normalize(text: str) -> str:
    return " ".join(text.split())


Hunks = tuple[tuple[int, int], ...]


def hunks_from_texts(
    base_text: str | None,
    head_text: str | None,
    context: int = HUNK_CONTEXT,
    work: linediff.WorkBudget | None = None,
) -> tuple[Hunks, Hunks]:
    """Inclusive 1-based (base, head) hunk ranges of a unified diff of two texts.

    The diff is bounded (`linediff`): by its size and by the work budget of
    the file and of the run (`work`, a fresh one when None). When it is past
    a budget the exact hunks are not known, so there are none: every finding
    in the file goes to the summary, and none is lost.
    """
    return _hunks(base_text, head_text, context, work)[:2]


def _hunks(
    base_text: str | None, head_text: str | None, context: int, work: linediff.WorkBudget | None
) -> tuple[Hunks, Hunks, str | None]:
    a = _lines(base_text) if base_text is not None else []
    b = _lines(head_text) if head_text is not None else []
    base_hunks: list[tuple[int, int]] = []
    head_hunks: list[tuple[int, int]] = []
    diff = linediff.diff(a, b, work=work)
    if not diff.exact:
        return (), (), diff.reason
    for group in linediff.hunks(diff.codes, context):
        i1, i2 = group[0][1], group[-1][2]
        j1, j2 = group[0][3], group[-1][4]
        if i2 > i1:
            base_hunks.append((i1 + 1, i2))
        if j2 > j1:
            head_hunks.append((j1 + 1, j2))
    return tuple(base_hunks), tuple(head_hunks), None


class _FileIndex:
    def __init__(self, files: Iterable[FileSides]) -> None:
        self.by_path: dict[str, FileSides] = {}
        self.by_old_path: dict[str, FileSides] = {}
        for f in files:
            self.by_path[f.path] = f
            if f.old_path is not None:
                self.by_old_path[f.old_path] = f

    def lookup(self, path: str, side: str) -> FileSides | None:
        if side == "base":
            # The old path of a rename names its base blob, also when an added
            # file reuses that path.
            found = self.by_old_path.get(path)
            if found is not None:
                return found
        return self.by_path.get(path)


def _verify(f: FileSides | None, side: str, line: int, quote: str) -> str | None:
    """None when the evidence is real, else why not."""
    if f is None:
        return "file is not in the changed files"
    if f.path in META_PATHS and side != "head":
        return "PR title and body are cited on side head"
    text = f.head_text if side == "head" else f.base_text
    if text is None:
        return f"no {side} content for this file"
    lines = _lines(text)
    if not 1 <= line <= len(lines):
        return f"line is not in the {side} blob"
    q = _normalize(quote)
    if not q:
        return "empty quote"
    if _REDACTION_MARKER_RE.fullmatch(q):
        if _normalize(lines[line - 1]) != q:
            return "cited line is not only that redaction marker"
        return None
    window = lines[max(0, line - 1 - QUOTE_WINDOW) : line + QUOTE_WINDOW]
    if q not in _normalize("\n".join(window)):
        return f"quote not found within {QUOTE_WINDOW} lines of the cited line"
    return None


def is_blocking(category: str, severity: str) -> bool:
    return category in BLOCKING_CATEGORIES and severity in BLOCKING_SEVERITIES


def cite_finding(
    pass_name: str, finding: Mapping[str, Any], files: Sequence[FileSides] | _FileIndex
) -> CitedFinding:
    """Citation check for one schema-valid finding.

    Quotes are compared with the redacted text the model saw, so a quote that
    holds a real credential value does not verify. The finding stays either way.
    """
    index = files if isinstance(files, _FileIndex) else _FileIndex(files)
    side = finding["side"]
    line = finding["line"]
    f = index.lookup(finding["file"], side)
    why = _verify(f, side, line, finding["quote"])
    verified = why is None
    inline = False
    if verified and f is not None and f.path not in META_PATHS:
        hunks = f.head_hunks if side == "head" else f.base_hunks
        inline = any(start <= line <= end for start, end in hunks)
    return CitedFinding(
        pass_name=pass_name,
        category=finding["category"],
        severity=finding["severity"],
        confidence=finding["confidence"],
        file=finding["file"],
        side=side,
        line=line,
        quote=finding["quote"],
        title=finding["title"],
        explanation=finding["explanation"],
        verified=verified,
        inline=inline,
        # Blocking never depends on verification.
        blocking=is_blocking(finding["category"], finding["severity"]),
        unverified_reason=why,
    )


# ---------------------------------------------------------------- overrides


def push_epoch(timeline: Timeline) -> tuple[datetime | None, bool]:
    """Return (epoch, ok). ok is False when the timeline is not fully readable.

    The epoch is the newest time of a `PUSH_EPOCH_EVENTS` event, or None when
    there is none.
    """
    if not timeline.complete:
        return None, False
    epoch: datetime | None = None
    for ev in timeline.events:
        if ev.event not in PUSH_EPOCH_EVENTS:
            continue
        if ev.created_at is None:
            return None, False
        if epoch is None or ev.created_at > epoch:
            epoch = ev.created_at
    return epoch, True


def _seconds(t: datetime) -> datetime:
    return t.replace(microsecond=0)


def _override_rejection(
    c: Comment,
    m: re.Match[str] | None,
    reason: str,
    inputs: OverrideInputs,
    snapshot: SnapshotPair | None,
    epoch: datetime | None,
    timeline_ok: bool,
    permissions: Mapping[str, str | None],
) -> str | None:
    if c.author_login.lower() == inputs.bot_login.lower() or c.author_type == "Bot":
        return OV_BOT_AUTHOR
    if m is None or not _SHA_RE.fullmatch(m.group(1)) or not _SHA_RE.fullmatch(m.group(2)):
        return OV_MALFORMED
    if not reason:
        return OV_EMPTY_REASON
    if snapshot is None:
        return OV_NO_SNAPSHOT
    if m.group(1) != snapshot.head_sha:
        return OV_WRONG_HEAD
    if m.group(2) != snapshot.merge_base_sha:
        return OV_WRONG_MERGE_BASE
    if not timeline_ok:
        return OV_TIMELINE_INCOMPLETE
    if epoch is not None and not _seconds(c.created_at) > _seconds(epoch):
        return OV_BEFORE_EPOCH
    if c.updated_at != c.created_at:
        return OV_EDITED
    if c.author_login.lower() == inputs.pr_author.lower():
        return OV_PR_AUTHOR
    if permissions.get(c.author_login.lower()) not in OVERRIDE_PERMISSIONS:
        return OV_NO_PERMISSION
    return None


def evaluate_overrides(
    inputs: OverrideInputs, snapshot: SnapshotPair | None
) -> tuple[OverrideCandidate, ...]:
    """Every comment that starts with `/oc-review`, valid or with its rejection code.

    The whole comment body (trimmed) must be the one command line.
    """
    epoch, timeline_ok = push_epoch(inputs.timeline)
    permissions = {k.lower(): v for k, v in inputs.permissions.items()}
    out = []
    for c in sorted(inputs.comments, key=lambda c: c.id):
        text = c.body.strip()
        if not text.startswith(OVERRIDE_PREFIX):
            continue
        m = _OVERRIDE_RE.fullmatch(text)
        reason = (m.group(3) or "").strip() if m else ""
        rejection = _override_rejection(
            c, m, reason, inputs, snapshot, epoch, timeline_ok, permissions
        )
        out.append(
            OverrideCandidate(
                comment_id=c.id,
                author_login=c.author_login,
                html_url=c.html_url,
                created_at=c.created_at,
                reason=reason,
                rejection=rejection,
            )
        )
    return tuple(out)


def find_sticky_comment(comments: Iterable[Comment], bot_login: str = BOT_LOGIN) -> Comment | None:
    """The sticky summary to update: the marker and the bot author, oldest first.

    A marker from any other author is ignored. The sticky is never a trust
    source for the gate.
    """
    own = [c for c in comments if STICKY_MARKER in c.body and c.author_login == bot_login]
    return min(own, key=lambda c: c.id) if own else None


# ---------------------------------------------------------------- gate


def _validated(read: ArtifactRead, kind: str, label: str) -> tuple[Mapping[str, Any] | None, list[Reason]]:
    """The envelope when it is schema-valid and of `kind`, else an `artifact` reason."""
    if read.error is not None or read.envelope is None:
        return None, [Reason(R_ARTIFACT, f"{label}: {read.error or 'no envelope'}")]
    doc = read.envelope
    try:
        envelope.validate_envelope(doc)
    except envelope.EnvelopeError as exc:
        return None, [Reason(R_ARTIFACT, f"{label}: {exc}")]
    if doc["kind"] != kind:
        return None, [Reason(R_ARTIFACT, f"{label}: kind {doc['kind']}, expected {kind}")]
    return doc, []


def _context_reasons(
    doc: Mapping[str, Any], label: str, ctx: RunContext, snapshot: Mapping[str, Any] | None
) -> list[Reason]:
    """An envelope that does not match the run or the snapshot is still used:
    its data can only add reasons, and the `artifact` reason is not waivable."""
    if snapshot is None:
        return [Reason(R_ARTIFACT, f"{label}: no bundle snapshot to match")]
    try:
        envelope.check_context(
            doc,
            repository_id=ctx.repository_id,
            pr_number=ctx.pr_number,
            run_id=ctx.run_id,
            run_attempt=ctx.run_attempt,
            snapshot=snapshot,
        )
    except envelope.EnvelopeError as exc:
        return [Reason(R_ARTIFACT, f"{label}: {exc}")]
    return []


def _frozen(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _frozen(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_frozen(v) for v in value)
    return value


def _pass_info(doc: Mapping[str, Any]) -> PassInfo:
    meta = doc.get("meta")
    payload = doc["payload"]
    summary = payload.get("summary") if isinstance(payload, Mapping) else None
    return PassInfo(
        name=doc["pass"],
        status=doc["status"],
        summary=summary if isinstance(summary, str) else None,
        meta=_frozen(meta) if isinstance(meta, Mapping) else MappingProxyType({}),
    )


def _failed_detail(info: PassInfo) -> str:
    """`pass X failed`, with the analyze reason from `meta` when it has one
    (for example "workspace spend limit reached")."""
    reason = info.meta.get("reason")
    if isinstance(reason, str) and reason.strip():
        return f"pass {info.name} failed: {reason.strip()[:200]}"
    return f"pass {info.name} failed"


def _job_reasons(job_results: Mapping[str, str], outcome: str | None) -> list[Reason]:
    out = []
    for job in REQUIRED_JOBS:
        result = job_results.get(job)
        if result != "success":
            out.append(Reason(R_JOB_RESULT, f"{job}: {result or 'missing'}"))
    dr_job = job_results.get(DEPENDENCY_REVIEW_JOB)
    if dr_job != "success":
        out.append(Reason(R_DEPENDENCY_REVIEW, f"job result {dr_job or 'missing'}"))
    if outcome != "success":
        out.append(Reason(R_DEPENDENCY_REVIEW, f"step outcome {outcome or 'missing'}"))
    return out


def _revalidation_reasons(check: SnapshotCheck | None) -> list[Reason]:
    if check is None:
        return [Reason(R_STALE, NOT_REVALIDATED)]
    out = [Reason(R_STALE, str(r)) for r in check.stale_reasons]
    if check.base_not_default_branch:
        out.append(Reason(R_BASE_NOT_DEFAULT, "base ref is not the default branch"))
    return out


def _prefilter_reasons(
    evidence: PrefilterEvidence | None,
    bundle: Mapping[str, Any] | None,
    snapshot: SnapshotPair | None,
) -> list[Reason]:
    """Union of the hard blocks in the bundle payload and in the prefilter
    evidence; nothing here removes one. Missing, incomplete or unbound
    evidence is itself a hard block reason (not waivable)."""
    out = []
    if bundle is not None:
        out += [Reason(R_HARD_BLOCK, b) for b in _bundle_hard_blocks(bundle)]
    if evidence is None:
        out.append(Reason(R_HARD_BLOCK, "prefilter result missing"))
        return out
    out += [Reason(R_HARD_BLOCK, str(b)) for b in evidence.hard_blocks]
    if evidence.state != PREFILTER_COMPLETE:
        out.append(Reason(R_HARD_BLOCK, f"prefilter result unavailable: {evidence.detail or evidence.state}"))
    elif snapshot is None or (evidence.head_sha, evidence.merge_base_sha) != (
        snapshot.head_sha,
        snapshot.merge_base_sha,
    ):
        out.append(Reason(R_HARD_BLOCK, "prefilter result is not for the bundle snapshot"))
    return out


def _decide(reasons: Sequence[Reason], overrides: Sequence[OverrideCandidate]) -> tuple[str, bool]:
    """(status, override_applied). Pass only with no reason, or with waivable
    reasons only and a valid override."""
    if not reasons:
        return PASS, False
    if all(r.waivable for r in reasons) and any(c.valid for c in overrides):
        return PASS, True
    return FAIL, False


def _unique(reasons: Iterable[Reason]) -> tuple[Reason, ...]:
    return tuple(dict.fromkeys(reasons))


def compute_gate(inputs: GateInputs) -> GateResult:
    ctx = inputs.context
    reasons = _job_reasons(inputs.job_results, inputs.dependency_review_outcome)

    # The bundle carries the snapshot every other envelope must match.
    bundle, rs = _validated(inputs.bundle, "bundle", "bundle")
    reasons += rs
    snap_fields: Mapping[str, Any] | None = None
    snapshot: SnapshotPair | None = None
    bundle_size = False
    if bundle is not None:
        snap_fields = {f: bundle[f] for f in envelope.SNAPSHOT_FIELDS}
        snapshot = SnapshotPair(bundle["head_sha"], bundle["merge_base_sha"], bundle["base_ref"])
        reasons += _context_reasons(bundle, "bundle", ctx, snap_fields)
        status = bundle["status"]
        if status == "stale":
            reasons.append(Reason(R_STALE, "bundle status stale"))
        elif status == "skipped-size":
            bundle_size = True
            reasons.append(Reason(R_SIZE_GATE, "too large for automatic review"))
        elif status == "failed":
            reasons.append(Reason(R_ARTIFACT, "bundle status failed"))

    # Exactly three pass records, one per pass.
    if len(inputs.passes) != len(PASS_NAMES):
        reasons.append(
            Reason(R_PASS_RECORDS, f"expected {len(PASS_NAMES)} pass records, got {len(inputs.passes)}")
        )
    index = _FileIndex(inputs.files)
    findings: list[CitedFinding] = []
    infos: list[PassInfo] = []
    names: Counter[str] = Counter()
    for i, read in enumerate(inputs.passes):
        label = f"pass record {i + 1}"
        doc, rs = _validated(read, "pass", label)
        reasons += rs
        if doc is None:
            continue
        reasons += _context_reasons(doc, label, ctx, snap_fields)
        info = _pass_info(doc)
        infos.append(info)
        name = doc["pass"]
        names[name] += 1
        status = doc["status"]
        if status == "failed":
            reasons.append(Reason(R_PASS_RECORDS, _failed_detail(info)))
        elif status == "stale":
            reasons.append(Reason(R_STALE, f"pass {name} stale"))
        elif status == "skipped-size":
            if not bundle_size:
                reasons.append(Reason(R_SIZE_GATE, f"pass {name} skipped for size"))
                reasons.append(Reason(R_ARTIFACT, f"pass {name} skipped-size, bundle is not"))
        elif status == "ok":
            if bundle_size:
                reasons.append(Reason(R_ARTIFACT, f"pass {name} ran, bundle is skipped-size"))
            pass_findings = doc["payload"]["findings"]
            limit = PASS_MAX_FINDINGS[name]
            if len(pass_findings) > limit:
                reasons.append(
                    Reason(R_PASS_RECORDS, f"pass {name} invalid: {len(pass_findings)} findings, limit {limit}")
                )
            for finding in pass_findings:
                findings.append(cite_finding(name, finding, index))
    for name in PASS_NAMES:
        if names[name] == 0:
            reasons.append(Reason(R_PASS_RECORDS, f"missing pass record {name}"))
        elif names[name] > 1:
            reasons.append(Reason(R_PASS_RECORDS, f"duplicate pass record {name}"))

    reasons += _revalidation_reasons(inputs.revalidation)
    reasons += _prefilter_reasons(inputs.prefilter, bundle, snapshot)
    reasons += [
        Reason(R_BLOCKING_FINDING, f"{f.pass_name}: {f.category} {f.severity} at {f.file}:{f.line}")
        for f in findings
        if f.blocking
    ]

    final_reasons = _unique(reasons)
    overrides = evaluate_overrides(inputs.overrides, snapshot)
    status, applied = _decide(final_reasons, overrides)
    return GateResult(
        status=status,
        run_id=ctx.run_id,
        reasons=final_reasons,
        findings=tuple(findings),
        snapshot=snapshot,
        overrides=overrides,
        override_applied=applied,
        passes=tuple(infos),
    )


def _workflow_path_matches(path: str | None, workflow_path: str) -> bool:
    if path is None:
        return True  # unknown path: assume it is the central workflow (fail closed)
    p = path.split("@", 1)[0]
    return p == workflow_path or p.endswith("/" + workflow_path)


def superseded_reason(
    runs: RunList, run_id: int, workflow_path: str = WORKFLOW_PATH
) -> Reason | None:
    """A run of the central workflow path with a higher run ID on the head SHA.
    A same-path workflow in the target repo also matches; that can only block."""
    if not runs.complete:
        return Reason(R_SUPERSEDED, "run list could not be read completely")
    newer = [r.id for r in runs.runs if r.id > run_id and _workflow_path_matches(r.path, workflow_path)]
    if newer:
        return Reason(R_SUPERSEDED, f"newer run {max(newer)} on the head SHA")
    return None


def final_check(
    initial: GateResult,
    *,
    revalidation: SnapshotCheck | None,
    overrides: OverrideInputs,
    runs: RunList,
    workflow_path: str = WORKFLOW_PATH,
) -> GateResult:
    """The last step before exit: snapshot, override authority and run list read again.

    It can only keep or lower the result: a run that was `fail` stays `fail`.
    """
    reasons = list(initial.reasons) + _revalidation_reasons(revalidation)
    sup = superseded_reason(runs, initial.run_id, workflow_path)
    if sup is not None:
        reasons.append(sup)
    final_reasons = _unique(reasons)
    candidates = evaluate_overrides(overrides, initial.snapshot)
    status, applied = _decide(final_reasons, candidates)
    if initial.status != PASS:
        status, applied = FAIL, False
    return GateResult(
        status=status,
        run_id=initial.run_id,
        reasons=final_reasons,
        findings=initial.findings,
        snapshot=initial.snapshot,
        overrides=candidates,
        override_applied=applied,
        passes=initial.passes,
    )
