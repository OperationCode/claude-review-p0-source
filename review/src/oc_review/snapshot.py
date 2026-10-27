"""Comparison pair capture, re-validation and tree diff.

Every function takes API data that the caller already fetched (parsed JSON
dicts). No function here does I/O. All input is untrusted: a malformed shape
raises `SnapshotError` and the caller fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Stale reasons (spec "Consistent snapshot", Re-validate).
STALE_HEAD_SHA = "head_sha_changed"
STALE_BASE_REPOSITORY = "base_repository_changed"
STALE_BASE_REF = "base_ref_changed"
STALE_MERGE_BASE = "merge_base_changed"

MODE_SYMLINK = "120000"
MODE_SUBMODULE = "160000"
MODE_TREE = "040000"

# The only git modes each tree entry type may carry. Any other pair is a
# malformed response, never a skipped entry.
_TYPE_MODES = {
    "tree": frozenset({MODE_TREE}),
    "blob": frozenset({"100644", "100755", MODE_SYMLINK}),
    "commit": frozenset({MODE_SUBMODULE}),
}

STATUS_ADDED = "added"
STATUS_REMOVED = "removed"
STATUS_MODIFIED = "modified"
STATUS_RENAMED = "renamed"


class SnapshotError(Exception):
    """API data has an unexpected shape. The caller fails closed."""


class StaleSnapshot(Exception):
    """The run is `stale`. It stops and writes nothing more."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__("stale: " + ", ".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class Snapshot:
    head_sha: str
    base_repository_id: int
    base_ref: str
    base_tip_sha: str
    merge_base_sha: str


@dataclass(frozen=True)
class Revalidation:
    """Result of a re-check against the current PR state.

    `stale_reasons` holds the stale conditions. `base_not_default_branch` is a
    separate, not-waivable gate reason; it is not a stale condition.
    """

    stale_reasons: tuple[str, ...]
    base_not_default_branch: bool

    @property
    def stale(self) -> bool:
        return bool(self.stale_reasons)

    @property
    def ok(self) -> bool:
        return not self.stale_reasons and not self.base_not_default_branch


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str  # added | removed | modified | renamed
    old_path: str | None  # renames only
    base_sha: str | None  # None for added; for a submodule, the old commit SHA
    head_sha: str | None  # None for removed; for a submodule, the new commit SHA
    base_mode: str | None
    head_mode: str | None

    @property
    def mode_changed(self) -> bool:
        return (
            self.base_mode is not None
            and self.head_mode is not None
            and self.base_mode != self.head_mode
        )

    @property
    def mode_only(self) -> bool:
        """Same blob SHA at the same path, different mode."""
        return (
            self.status == STATUS_MODIFIED
            and self.base_sha == self.head_sha
            and self.mode_changed
        )

    @property
    def became_executable(self) -> bool:
        """A regular file gained an execute bit (prefilter signal)."""
        special = (MODE_SYMLINK, MODE_SUBMODULE)
        if self.head_mode is None or self.head_mode in special:
            return False
        if int(self.head_mode, 8) & 0o111 == 0:
            return False
        if self.base_mode is None or self.base_mode in special:
            return True
        return int(self.base_mode, 8) & 0o111 == 0

    @property
    def is_symlink(self) -> bool:
        return MODE_SYMLINK in (self.head_mode, self.base_mode)

    @property
    def is_submodule(self) -> bool:
        return MODE_SUBMODULE in (self.head_mode, self.base_mode)


@dataclass(frozen=True)
class TreeDiff:
    files: tuple[ChangedFile, ...]  # sorted by path
    complete: bool  # False when either tree was truncated


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA_RE.match(value) is not None


def _require_sha(value: Any, what: str) -> str:
    if not _is_sha(value):
        raise SnapshotError(f"{what} is not a 40-character lowercase hex SHA")
    return value


def _get(obj: Any, *keys: str, what: str) -> Any:
    cur = obj
    for key in keys:
        if not isinstance(cur, Mapping) or key not in cur:
            raise SnapshotError(f"missing {what}")
        cur = cur[key]
    return cur


def _pr_view(pr: Mapping[str, Any]) -> tuple[str, int, str, str]:
    """Return head SHA, base repository ID, base ref, default branch."""
    head_sha = _require_sha(_get(pr, "head", "sha", what="pr.head.sha"), "pr.head.sha")
    repo_id = _get(pr, "base", "repo", "id", what="pr.base.repo.id")
    if isinstance(repo_id, bool) or not isinstance(repo_id, int):
        raise SnapshotError("pr.base.repo.id is not an integer")
    base_ref = _get(pr, "base", "ref", what="pr.base.ref")
    default_branch = _get(
        pr, "base", "repo", "default_branch", what="pr.base.repo.default_branch"
    )
    for value, what in ((base_ref, "pr.base.ref"), (default_branch, "default_branch")):
        if not isinstance(value, str) or not value:
            raise SnapshotError(f"{what} is not a non-empty string")
    return head_sha, repo_id, base_ref, default_branch


def merge_base_from_compare(compare: Mapping[str, Any], base_tip_sha: str) -> str:
    """Read the merge base from a compare response for `base_tip...head`.

    The response must be for the expected base tip, or the pair is wrong.
    """
    _require_sha(base_tip_sha, "base tip SHA")
    merge_base = _require_sha(
        _get(compare, "merge_base_commit", "sha", what="compare.merge_base_commit.sha"),
        "compare.merge_base_commit.sha",
    )
    base_commit = _get(compare, "base_commit", "sha", what="compare.base_commit.sha")
    if base_commit != base_tip_sha:
        raise SnapshotError("compare response is not for the expected base tip")
    return merge_base


def base_is_default_branch(pr: Mapping[str, Any]) -> bool:
    _, _, base_ref, default_branch = _pr_view(pr)
    return base_ref == default_branch


def capture_snapshot(
    pr: Mapping[str, Any],
    base_tip_sha: str,
    compare: Mapping[str, Any],
    event_head_sha: str,
) -> Snapshot:
    """Capture the comparison pair.

    `pr` is the PR read through the API, `base_tip_sha` the current tip of the
    base ref, `compare` the compare response for `base_tip...head`.
    Raises `StaleSnapshot` when the PR head differs from the event's head.
    """
    _require_sha(event_head_sha, "event head SHA")
    head_sha, repo_id, base_ref, _ = _pr_view(pr)
    if head_sha != event_head_sha:
        raise StaleSnapshot((STALE_HEAD_SHA,))
    return Snapshot(
        head_sha=head_sha,
        base_repository_id=repo_id,
        base_ref=base_ref,
        base_tip_sha=_require_sha(base_tip_sha, "base tip SHA"),
        merge_base_sha=merge_base_from_compare(compare, base_tip_sha),
    )


def check_head_and_base_ref(snapshot: Snapshot, pr: Mapping[str, Any]) -> Revalidation:
    """Analyze's check before the first Claude call: head SHA and base ref."""
    head_sha, _, base_ref, default_branch = _pr_view(pr)
    stale = []
    if head_sha != snapshot.head_sha:
        stale.append(STALE_HEAD_SHA)
    if base_ref != snapshot.base_ref:
        stale.append(STALE_BASE_REF)
    return Revalidation(tuple(stale), base_ref != default_branch)


def revalidate(
    snapshot: Snapshot,
    pr: Mapping[str, Any],
    current_base_tip_sha: str,
    compare: Mapping[str, Any],
) -> Revalidation:
    """The publisher's full check: head SHA, base repository, base ref, merge base.

    `current_base_tip_sha` is the base ref's tip now and `compare` the compare
    response for `current_base_tip_sha...head`, so the merge base is recomputed.
    """
    head_sha, repo_id, base_ref, default_branch = _pr_view(pr)
    merge_base = merge_base_from_compare(compare, current_base_tip_sha)
    stale = []
    if head_sha != snapshot.head_sha:
        stale.append(STALE_HEAD_SHA)
    if repo_id != snapshot.base_repository_id:
        stale.append(STALE_BASE_REPOSITORY)
    if base_ref != snapshot.base_ref:
        stale.append(STALE_BASE_REF)
    if merge_base != snapshot.merge_base_sha:
        stale.append(STALE_MERGE_BASE)
    return Revalidation(tuple(stale), base_ref != default_branch)


def _entries(tree: Mapping[str, Any], side: str) -> tuple[dict[str, tuple[str, str, str]], bool]:
    """Map path -> (mode, type, sha) for blobs and submodules; and `complete`."""
    items = _get(tree, "tree", what=f"{side} tree entries")
    if not isinstance(items, list):
        raise SnapshotError(f"{side} tree entries are not a list")
    # A response with no `truncated` key fails closed: a default of False
    # would drop the "incomplete coverage" hard block.
    truncated = _get(tree, "truncated", what=f"{side} tree truncated flag")
    if not isinstance(truncated, bool):
        raise SnapshotError(f"{side} tree truncated flag is not a boolean")
    out: dict[str, tuple[str, str, str]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise SnapshotError(f"{side} tree entry is not an object")
        path, mode, kind, sha = (item.get(k) for k in ("path", "mode", "type", "sha"))
        if not isinstance(path, str) or not path:
            raise SnapshotError(f"{side} tree entry has no path")
        if not isinstance(kind, str) or kind not in _TYPE_MODES:
            raise SnapshotError(f"{side} tree entry {path!r} has a bad type")
        # Check the pair before a directory is skipped, so a blob mode on a
        # `tree` entry cannot drop a file from the comparison.
        if not isinstance(mode, str) or mode not in _TYPE_MODES[kind]:
            raise SnapshotError(f"{side} tree entry {path!r} type and mode disagree")
        _require_sha(sha, f"{side} tree entry {path!r} sha")
        if path in out:
            raise SnapshotError(f"{side} tree has duplicate path {path!r}")
        if kind == "tree":
            continue
        out[path] = (mode, kind, sha)
    return out, not truncated


def diff_trees(base_tree: Mapping[str, Any], head_tree: Mapping[str, Any]) -> TreeDiff:
    """Changed file list from two recursive tree responses, by path.

    Compares blob SHA and mode. A rename is a removed and an added path with
    the same blob SHA, paired one to one in path order; everything else is a
    delete plus an add. Submodules never pair as renames.
    """
    base, base_ok = _entries(base_tree, "base")
    head, head_ok = _entries(head_tree, "head")

    changed: list[ChangedFile] = []
    removed: dict[str, tuple[str, str, str]] = {}
    added: dict[str, tuple[str, str, str]] = {}
    for path in sorted(base.keys() | head.keys()):
        b, h = base.get(path), head.get(path)
        if b is None:
            added[path] = h  # type: ignore[assignment]
        elif h is None:
            removed[path] = b
        elif b[0] != h[0] or b[2] != h[2]:
            changed.append(
                ChangedFile(path, STATUS_MODIFIED, None, b[2], h[2], b[0], h[0])
            )

    # Pair renames: same blob SHA, one to one, in path order.
    by_sha: dict[str, list[str]] = {}
    for path, (_, kind, sha) in removed.items():
        if kind == "blob":
            by_sha.setdefault(sha, []).append(path)
    for path in sorted(added):
        mode, kind, sha = added[path]
        candidates = by_sha.get(sha)
        if kind == "blob" and candidates:
            old = candidates.pop(0)
            old_mode = removed.pop(old)[0]
            del added[path]
            changed.append(ChangedFile(path, STATUS_RENAMED, old, sha, sha, old_mode, mode))

    for path, (mode, _, sha) in added.items():
        changed.append(ChangedFile(path, STATUS_ADDED, None, None, sha, None, mode))
    for path, (mode, _, sha) in removed.items():
        changed.append(ChangedFile(path, STATUS_REMOVED, None, sha, None, mode, None))

    changed.sort(key=lambda f: (f.path, f.old_path or ""))
    return TreeDiff(tuple(changed), base_ok and head_ok)
