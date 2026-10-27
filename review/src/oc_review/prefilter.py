"""Deterministic prefilter checks and coverage (spec "Prefilter checks (no LLM)"
and "Coverage limits").

No LLM reads anything here, and nothing here fetches, runs or writes PR
content. Inputs are in memory: the tree diff from `snapshot.diff_trees`, the
blobs by SHA, and the dependency facts that collect builds with `deps.py`.

Rules this module keeps:

- Every changed text blob is scanned in full, up to `MAX_BLOB_BYTES`, whatever
  its line count. A blob that cannot be read, decoded as UTF-8 text, or is over
  the cap has coverage `unavailable`, which is the hard block "incomplete
  coverage".
- Hard blocks are decided here, by code. Claude output cannot clear them.
- Evidence never carries a credential value. Fields that hold PR text
  (`file`, `subject`) are untrusted; the publisher escapes them.
"""

from __future__ import annotations

import bisect
import codecs
import hashlib
import json
import re
import sys
import tomllib
import unicodedata
from array import array
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from oc_review import deps, render
from oc_review.snapshot import MODE_SUBMODULE, MODE_SYMLINK, ChangedFile, TreeDiff

# Hard cap on the bytes of one blob that the prefilter scans. Matches the cap
# on one dependency file in deps.py, so a lockfile deps.py can parse is never
# over this cap.
MAX_BLOB_BYTES = 16 * 1024 * 1024
# A blob is binary when its first bytes hold a NUL and it is not valid UTF-8
# (the same window git uses to call a file binary).
BINARY_SNIFF_BYTES = 8000
# Ruling R-BIN: such a blob counts as binary only when its path has one of
# these extensions (images, fonts, archives, compiled objects). Any other path
# gets coverage `unavailable`, so binary bytes cannot hide source text.
BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar", ".jar",
    ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".class", ".pyc", ".wasm",
})
# Line numbers kept per check and file; `count` keeps the full total.
MAX_LINES_PER_CHECK = 20
# A package version published less than this long ago is a hard block.
FRESH_PUBLISH_WINDOW = timedelta(hours=72)
LONG_LINE_CHARS = 500
BLOB_RUN_CHARS = 200
# Steps the line diff may take for one file. Past it, every head line between
# the common prefix and suffix counts as changed.
DIFF_WORK_BUDGET = 2_000_000
# Steps the line diffs of all files of one `run_prefilter` call may take
# together. Measured on an Apple M-series core: about 7 s of diff time.
RUN_DIFF_WORK_BUDGET = 40_000_000

PAST_FILE_DIFF_BUDGET = "line diff past the per-file work budget"
PAST_RUN_DIFF_BUDGET = "line diff past the run work budget"


class DiffBudget:
    """Line diff work left for one `run_prefilter` call. Every file takes from
    it: a file gets `min(per_file, left)` steps, and is charged the steps it
    used, or everything it was allowed when it went past its allowance."""

    def __init__(self, total: int = RUN_DIFF_WORK_BUDGET, per_file: int = DIFF_WORK_BUDGET) -> None:
        self.left = total
        self.per_file = per_file

Level = Literal["hard_block", "signal"]
CoverageKind = Literal["full", "binary", "unavailable"]

HARD_BLOCK: Level = "hard_block"
SIGNAL: Level = "signal"

# Check IDs. The gate only reads the level; the IDs are for the summary.
BIDI_CONTROL = "bidi-control"
BIDI_PATH = "bidi-control-in-path"
FOREIGN_SOURCE = "foreign-source"
FRESH_PUBLISH = "fresh-publish"
INCOMPLETE_COVERAGE = "incomplete-coverage"
INCOMPLETE_DEP_DATA = "incomplete-dependency-data"
BASE_DEP_UNPARSED = "base-dependency-file-unparsed"
ZERO_WIDTH = "zero-width"
INVISIBLE_CHAR = "invisible-character"
AI_DIRECTED_TEXT = "ai-directed-text"
CREDENTIAL = "credential-like-string"
INSTALL_SCRIPT_DEP = "dependency-install-script"
INSTALL_SCRIPT_CHANGE = "package-json-install-script"
SDIST_ONLY = "pypi-sdist-only"
MANIFEST_WITHOUT_LOCKFILE = "manifest-without-lockfile"
UNSUPPORTED_DEP_FILE = "unsupported-dependency-file"
SENSITIVE_PATH = "sensitive-path"
BUILD_SYSTEM_CHANGE = "pyproject-build-system"
BINARY_ADDED = "binary-file"
SUBMODULE = "submodule-change"
EXECUTABLE = "became-executable"
MINIFIED_JS = "minified-js"
LONG_LINE = "long-line"
ENCODED_BLOB = "encoded-blob"
FIRST_TIME_AUTHOR = "first-time-contributor"

# --- character classes ------------------------------------------------------

# Spec: U+202A to U+202E and U+2066 to U+2069 (Trojan Source).
_BIDI_RE = re.compile("[‪-‮⁦-⁩]")
# Spec: U+200B to U+200D, U+2060, U+FEFF (FEFF allowed at file start only).
_ZERO_WIDTH_RE = re.compile("[​-‍⁠﻿]")
# Coordinator-approved addition (see report "Spec follow-up"): invisible
# characters the zero-width row misses. FE00-FE0F are left out: emoji use them.
_INVISIBLE_RE = re.compile(
    "[­͏؜ᅟᅠ᠎‎‏⁡-⁤ㅤﾠ"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

_BOMS_UNSUPPORTED = (
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\x00\x00\xfe\xff",  # UTF-32 BE
    b"\xff\xfe",  # UTF-16 LE
    b"\xfe\xff",  # UTF-16 BE
)
# PEP 263 coding cookie, first two lines only.
_CODING_RE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)", re.ASCII)
_UTF8_CODECS = frozenset({"utf-8", "utf-8-sig", "ascii"})

# --- credentials --------------------------------------------------------------

# Credential kinds and patterns live in render.py, so the credential signal
# reports every kind that render redacts (see `find_credentials`).

# --- text that addresses an AI or reviewer ------------------------------------

# Patterns run on normalized text (see `normalize_for_match`): NFKD, no marks or
# format characters, casefolded, common homoglyphs folded to Latin, and runs of
# whitespace and light punctuation collapsed to one space.
_AI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        (
            "ignore-instructions",
            r"\b(?:ignore|disregard|forget|override) (?:(?:all|any|the|previous|prior|above|earlier"
            r"|your|of|these|those|system) ){1,4}(?:instructions?|rules|guidelines|prompts?)\b",
        ),
        ("as-an-ai", r"\bas an ai\b"),
        ("system-prompt", r"\bsystem prompt\b"),
        ("you-are-now", r"\byou are (?:now )?an? \w"),
        ("reviewer-address", r"\breviewer ?:"),
        ("ai-reviewer", r"\b(?:ai|llm|claude|gpt|chatgpt|model) (?:reviewer|assistant|agent)\b"),
        ("system-tag", r"< ?/? ?system ?>"),
        ("instructions-tag", r"< ?/ ?instructions ?>"),
        ("delimiter-tag", r"< ?/? ?untrusted pr"),
        ("chat-template", r"<\|(?:im start|im end|system|endoftext)\|>|\[/?inst\]"),
    )
)

# Lowercase Cyrillic and Greek letters that look like Latin ones.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j",
        "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s",
        "т": "t", "у": "y", "ԝ": "w", "х": "x", "ү": "y",
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
        "υ": "u", "χ": "x", "ѵ": "v",
    }
)
_SEPARATORS_RE = re.compile(r"[\s_\-*~.,'\"`+]+")
_COMMENT_LEADER_RE = re.compile(r"^\s*(?:#+|//+|/\*+|\*+/?|--+|<!--|;+|%+|>+)\s*")
_DROP_CATEGORIES = frozenset({"Mn", "Me", "Cf"})

# --- encoded blobs ----------------------------------------------------------

_B64_CLASS = r"A-Za-z0-9+/=_\-"
_B64_RUN_RE = re.compile(rf"(?<![{_B64_CLASS}])[{_B64_CLASS}]{{{BLOB_RUN_CHARS + 1},}}")
_HEX_ONLY_RE = re.compile(r"[0-9A-Fa-f]+")
_ESCAPED_RUN_RE = re.compile(
    r"(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2}, ?)+"
)
# One line of a base64 blob that was wrapped over several lines.
_WRAPPED_B64_LINE_RE = re.compile(r"^\s*[\"'`]?([A-Za-z0-9+/]{40,}={0,2})[\"'`]?\s*[,;+]?\s*$")

# --- paths ------------------------------------------------------------------

# Install lifecycle scripts; one list with the registry manifest check.
_INSTALL_SCRIPTS = deps.NPM_LIFECYCLE_SCRIPTS
# Dependency files deps.py does not parse yet, on top of deps.UNSUPPORTED_DEP_FILES.
_EXTRA_UNSUPPORTED_DEP_FILES = frozenset({"npm-shrinkwrap.json", ".pnpmfile.cjs", "deno.json", "deno.lock"})
_JS_SUFFIXES = (".js", ".mjs", ".cjs")
_BUNDLE_MARKERS = ("__webpack_require__", "__webpack_modules__", "/******/", "parcelRequire", "//# sourceMappingURL=")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Check:
    """One prefilter result. One record per check, file and subject.

    `file` and `subject` hold PR text (paths, package names, versions) and are
    untrusted. `detail` is built by this module only. No field ever holds a
    credential value or the matched text of a content check.
    """

    id: str
    level: Level
    detail: str
    file: str | None = None
    subject: str | None = None
    lines: tuple[int, ...] = ()
    count: int = 1


@dataclass(frozen=True)
class FileCoverage:
    path: str
    coverage: CoverageKind
    reason: str | None = None  # why `unavailable`


@dataclass(frozen=True)
class Coverage:
    trees_complete: bool
    files_in_comparison: int
    files_collected: int
    files: tuple[FileCoverage, ...]

    @property
    def complete(self) -> bool:
        return self.trees_complete and all(f.coverage != "unavailable" for f in self.files)


@dataclass(frozen=True)
class PrefilterResult:
    signals: tuple[Check, ...]
    hard_blocks: tuple[Check, ...]
    coverage: Coverage

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready part of the bundle payload: the `prefilter` and
        `coverage` keys of the envelope schema. Collect adds the rest."""
        return _json_lists({
            "prefilter": {
                "signals": [asdict(c) for c in self.signals],
                "hard_blocks": [asdict(c) for c in self.hard_blocks],
            },
            "coverage": {**asdict(self.coverage), "complete": self.coverage.complete},
        })


def _json_lists(value: Any) -> Any:
    """`asdict` keeps tuples; the bundle (and render) take JSON lists only."""
    if isinstance(value, dict):
        return {k: _json_lists(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_lists(v) for v in value]
    return value


@dataclass(frozen=True)
class DepFailure:
    """A supported dependency file that did not parse, has an unknown format
    version, or a registry lookup that still failed after retries."""

    path: str
    reason: str


@dataclass(frozen=True)
class DependencyFacts:
    """What collect hands the prefilter, built with deps.py.

    - `parsed_paths`: changed supported files (deps.family_for_path) that
      parsed at the head. A changed supported file that is in neither this set
      nor `failures` is incomplete dependency data.
    - `changes`: deps.compute_delta for every parsed changed file.
    - `new_global_sources`: file-wide sources (pip index URLs) at the head that
      are not at the merge base.
    - `registry`: the deps.lookup_npm / deps.lookup_pypi result, keyed by
      `registry_key(change)`, for every change that has a key. The prefilter
      reads the publish time, npm install scripts and PyPI `has_wheel` from it.
    - `failures`: the hard block "incomplete dependency data", at most one
      per file.
    - `base_failures`: changed supported files whose merge-base side does not
      parse or has an unknown version. That side counts as empty, so every
      head entry is in `changes`. A signal only (ruling R-BASEDEPS).
    """

    parsed_paths: frozenset[str] = frozenset()
    changes: Sequence[deps.PackageChange] = ()
    new_global_sources: Sequence[deps.SourceIssue] = ()
    registry: Mapping[tuple[str, str, str], deps.RegistryInfo] = field(default_factory=dict)
    failures: Sequence[DepFailure] = ()
    base_failures: Sequence[DepFailure] = ()


@dataclass(frozen=True)
class BlobScan:
    """How the prefilter sees one blob."""

    kind: CoverageKind
    text: str | None = None  # set for `full` only
    reason: str | None = None  # set for `unavailable` only


# ---------------------------------------------------------------------------
# Blobs and coverage
# ---------------------------------------------------------------------------


def git_blob_sha(data: bytes, sha_len: int = 40) -> str:
    """Git object ID of a blob: SHA-1 (40 hex) or SHA-256 (64 hex)."""
    algo = hashlib.sha1 if sha_len == 40 else hashlib.sha256
    h = algo(f"blob {len(data)}\0".encode())
    h.update(data)
    return h.hexdigest()


def _declared_codec(data: bytes) -> str | None:
    """The codec a PEP 263 cookie in the first two lines names, if it is real."""
    for line in data.split(b"\n", 2)[:2]:
        m = _CODING_RE.match(line)
        if m:
            try:
                return codecs.lookup(m.group(1).decode("ascii")).name
            except LookupError:
                return None  # Python refuses such a file; nothing hides behind it
    return None


def has_binary_extension(path: str | None) -> bool:
    """True when the file name ends in one of `BINARY_EXTENSIONS` (any case)."""
    if not path:
        return False
    name = path.rsplit("/", 1)[-1].lower()
    return any(name.endswith(ext) for ext in BINARY_EXTENSIONS)


def scan_blob(
    data: bytes | None, *, sha: str | None = None, cap: int = MAX_BLOB_BYTES, path: str | None = None
) -> BlobScan:
    """Classify one blob as `full` text, `binary` or `unavailable`.

    Text is strict UTF-8 (a leading UTF-8 BOM is kept as U+FEFF). NUL bytes are
    allowed in text, so a NUL cannot hide a valid UTF-8 file from the scan. A
    blob over the cap is `unavailable` whatever its bytes: the spec allows no
    binary exception, and a NUL must not turn an over-cap text file into a
    signal. A blob that looks binary is `binary` only when `path` has a known
    binary extension (ruling R-BIN); otherwise, or with no path, it is
    `unavailable`.
    """
    if data is None:
        return BlobScan("unavailable", reason="unreadable")
    if sha is not None and git_blob_sha(data, len(sha)) != sha.lower():
        return BlobScan("unavailable", reason="sha-mismatch")
    if len(data) > cap:
        return BlobScan("unavailable", reason="over-cap")
    if data.startswith(_BOMS_UNSUPPORTED):
        return BlobScan("unavailable", reason="utf16-or-utf32")
    has_nul = b"\0" in data[:BINARY_SNIFF_BYTES]
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        if not has_nul:
            return BlobScan("unavailable", reason="undecodable")
        if not has_binary_extension(path):
            return BlobScan("unavailable", reason="binary-content-unknown-extension")
        return BlobScan("binary")
    if data.count(0) * 4 > len(data):
        # Valid UTF-8 but mostly NUL: UTF-16 or UTF-32 text without a BOM.
        return BlobScan("unavailable", reason="nul-heavy")
    codec = _declared_codec(data)
    if codec is not None and codec not in _UTF8_CODECS:
        return BlobScan("unavailable", reason="declared-encoding")
    return BlobScan("full", text=text)


_GITLINK = BlobScan("binary")


def _file_coverage(change: ChangedFile, base: BlobScan | None, head: BlobScan | None) -> FileCoverage:
    sides = [s for s in (head, base) if s is not None]
    for s in sides:
        if s.kind == "unavailable":
            return FileCoverage(change.path, "unavailable", s.reason)
    primary = head if head is not None else base
    if primary is None or primary.kind == "binary":
        return FileCoverage(change.path, "binary")
    return FileCoverage(change.path, "full")


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


class _Lines:
    """Line view of a text: lines split on LF only (git and GitHub line numbers)."""

    def __init__(self, text: str):
        self.text = text
        self.starts = [0]
        self.starts.extend(m.end() for m in re.finditer("\n", text))
        if self.starts[-1] == len(text) and len(self.starts) > 1:
            self.starts.pop()  # trailing newline: no empty last line
        self.lines = text.split("\n")
        if text.endswith("\n"):
            self.lines.pop()

    def line_of(self, offset: int) -> int:
        """1-based line number of a character offset."""
        return bisect.bisect_right(self.starts, offset)


def _added_lines(
    head: _Lines,
    base: _Lines | None,
    budget: int | None = None,
    run: DiffBudget | None = None,
    path: str = "",
) -> list[int]:
    """1-based head line numbers that a line diff of base to head adds.

    The common prefix and suffix are trimmed, then a Myers diff runs on the
    middle. Each base line matches at most one head line, in order, so a
    duplicate or a moved line counts as added. When the diff needs more than
    `budget` steps (default: the run's `per_file`, else `DIFF_WORK_BUDGET`),
    every head line in the middle counts as added: more lines than git shows,
    never fewer. With `run`, the file also takes from the
    run's budget (the left share never drops below 0), and past either limit
    stderr names the file and the limit. A file's work is bounded by its
    allowance plus one snake (at most the file's line count), not exactly by it.
    """
    if base is None:
        return list(range(1, len(head.lines) + 1))
    ids: dict[str, int] = {}
    a = [ids.setdefault(line, len(ids)) for line in base.lines]
    b = [ids.setdefault(line, len(ids)) for line in head.lines]
    pre = 0
    while pre < len(a) and pre < len(b) and a[pre] == b[pre]:
        pre += 1
    suf = 0
    while suf < len(a) - pre and suf < len(b) - pre and a[-1 - suf] == b[-1 - suf]:
        suf += 1
    a, b = a[pre : len(a) - suf], b[pre : len(b) - suf]
    if budget is None:
        budget = DIFF_WORK_BUDGET if run is None else run.per_file
    allowed = budget if run is None else max(0, min(budget, run.left))
    steps = [0]
    middle = _myers_inserts(a, b, allowed, steps)
    if run is not None:
        run.left = max(0, run.left - (allowed if middle is None else steps[0]))
    if middle is None:
        run_limited = run is not None and allowed < budget
        limit = PAST_RUN_DIFF_BUDGET if run_limited else PAST_FILE_DIFF_BUDGET
        # repr: the path is untrusted and may hold a newline that would start a workflow command
        print(f"prefilter: {(path or '(file)')!r}: {limit}; every changed line counts as added", file=sys.stderr)
        middle = list(range(len(b)))
    return [pre + j + 1 for j in middle]


def _myers_inserts(
    a: Sequence[int], b: Sequence[int], budget: int, steps: list[int] | None = None
) -> list[int] | None:
    """0-based indexes of `b` that a shortest edit script from `a` inserts.

    Myers' O((N+M)D) greedy algorithm. `trace[d][i]` is the furthest x on
    diagonal k = 2i - d after d edits. None when the work passes `budget`.
    `steps[0]` gets the work counted.
    """
    n, m = len(a), len(b)
    if not n or not m:
        return list(range(m))
    trace: list[array] = []
    prev = array("q")
    work = 0
    for d in range(n + m + 1):
        cur = array("q", bytes(8 * (d + 1)))
        for i in range(d + 1):
            k = 2 * i - d
            if d == 0:
                x = 0
            elif i == 0 or (i != d and prev[i - 1] < prev[i]):
                x = prev[i]  # down from diagonal k+1: insert b[y-1]
            else:
                x = prev[i - 1] + 1  # right from diagonal k-1: delete a[x-1]
            y = x - k
            start = x
            while x < n and y < m and a[x] == b[y]:
                x += 1
                y += 1
            work += 1 + x - start
            cur[i] = x
            if steps is not None:
                steps[0] = work
            if x >= n and y >= m:
                trace.append(cur)
                return _myers_backtrack(trace, n, m)
            if work > budget:
                return None
        trace.append(cur)
        prev = cur
    raise AssertionError("unreachable: a diff has at most n + m edits")


def _myers_backtrack(trace: Sequence[array], n: int, m: int) -> list[int]:
    inserts = []
    x, y = n, m
    for d in range(len(trace) - 1, 0, -1):
        prev = trace[d - 1]
        k = x - y
        i = (k + d) // 2
        if i == 0 or (i != d and prev[i - 1] < prev[i]):
            x = prev[i]
            y = x - (k + 1)
            inserts.append(y)
        else:
            x = prev[i - 1]
            y = x - (k - 1)
    inserts.reverse()
    return inserts


def normalize_for_match(text: str) -> str:
    """Fold Unicode tricks so a pattern sees what a human reads."""
    if not text.isascii():
        text = unicodedata.normalize("NFKD", text)
        text = "".join(c for c in text if unicodedata.category(c) not in _DROP_CATEGORIES)
    text = text.casefold().translate(_HOMOGLYPHS)
    return _SEPARATORS_RE.sub(" ", text)


def _ai_hits(lines: Sequence[str], changed: Iterable[int] | None = None) -> dict[str, list[int]]:
    """Run the AI-directed patterns over all `lines`, joined.

    Joining lets a phrase split over lines or comment markers match, and lets
    a changed line that completes a phrase with unchanged neighbors match.
    `changed` holds 1-based line numbers; a match counts only when it spans
    one, and is reported at the first changed line it spans. With no
    `changed`, every line counts. Returns pattern name -> line numbers.
    """
    flags = [changed is None] * len(lines)
    for n in changed or ():
        flags[n - 1] = True
    first_changed_at_or_after = [len(lines)] * (len(lines) + 1)
    for i in range(len(lines) - 1, -1, -1):
        first_changed_at_or_after[i] = i if flags[i] else first_changed_at_or_after[i + 1]

    # Lines that are empty after the comment leader is removed are left out of
    # the join, so a blank or bare comment line between two parts of a phrase
    # does not leave a double space that breaks the match.
    starts: list[int] = []
    line_of_part: list[int] = []
    parts: list[str] = []
    pos = 0
    for i, raw in enumerate(lines):
        norm = normalize_for_match(_COMMENT_LEADER_RE.sub("", raw)).strip()
        if not norm:
            continue
        starts.append(pos)
        line_of_part.append(i)
        parts.append(norm)
        pos += len(norm) + 1
    joined = " ".join(parts)
    hits: dict[str, list[int]] = {}
    for name, pattern in _AI_PATTERNS:
        for m in pattern.finditer(joined):
            first = line_of_part[bisect.bisect_right(starts, m.start()) - 1]
            last = line_of_part[bisect.bisect_right(starts, max(m.end() - 1, m.start())) - 1]
            hit = first_changed_at_or_after[first]
            if hit <= last:
                hits.setdefault(name, []).append(hit + 1)
    return hits


def find_credentials(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every credential-like string: the same detection
    that render.redact_text uses, so the signal and the redaction agree."""
    return render.find_credentials(text)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class _Results:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def add(
        self,
        check_id: str,
        level: Level,
        detail: str,
        *,
        file: str | None = None,
        subject: str | None = None,
        lines: Iterable[int] = (),
        count: int | None = None,
    ) -> None:
        line_list = sorted(set(lines))
        self.items.append(
            Check(
                id=check_id,
                level=level,
                detail=detail,
                file=file,
                subject=subject,
                lines=tuple(line_list[:MAX_LINES_PER_CHECK]),
                count=count if count is not None else max(1, len(line_list)),
            )
        )

    def lines_check(self, check_id: str, level: Level, detail: str, file: str, lines: list[int]) -> None:
        if lines:
            self.add(check_id, level, detail, file=file, lines=lines, count=len(lines))


def _codepoints(chars: Iterable[str]) -> str:
    return ", ".join(f"U+{ord(c):04X}" for c in sorted(set(chars)))


# ---------------------------------------------------------------------------
# Per-file checks
# ---------------------------------------------------------------------------


def _check_text(out: _Results, path: str, head: _Lines, added: list[int]) -> None:
    text = head.text
    added_set = set(added)

    # Bidi controls anywhere in the file: hard block.
    bidi = list(_BIDI_RE.finditer(text))
    if bidi:
        out.lines_check(
            BIDI_CONTROL, HARD_BLOCK,
            f"bidi control characters {_codepoints(m.group() for m in bidi)}",
            path, [head.line_of(m.start()) for m in bidi],
        )

    # Zero-width characters in changed lines (U+FEFF at file start is a BOM).
    zw = [m for m in _ZERO_WIDTH_RE.finditer(text) if not (m.start() == 0 and m.group() == "﻿")]
    zw_lines = [n for m in zw if (n := head.line_of(m.start())) in added_set]
    if zw_lines:
        chars = [m.group() for m in zw if head.line_of(m.start()) in added_set]
        out.lines_check(ZERO_WIDTH, SIGNAL, f"zero-width characters {_codepoints(chars)}", path, zw_lines)

    inv = [m for m in _INVISIBLE_RE.finditer(text) if head.line_of(m.start()) in added_set]
    if inv:
        out.lines_check(
            INVISIBLE_CHAR, SIGNAL,
            f"invisible characters {_codepoints(m.group() for m in inv)}",
            path, [head.line_of(m.start()) for m in inv],
        )

    # Credential-like strings in changed lines, by kind and location only.
    by_kind: dict[str, list[int]] = {}
    for kind, start, _ in find_credentials(text):
        n = head.line_of(start)
        if n in added_set:
            by_kind.setdefault(kind, []).append(n)
    for kind, lines in sorted(by_kind.items()):
        out.lines_check(CREDENTIAL, SIGNAL, f"{kind} (value redacted)", path, lines)

    # Text that addresses an AI or reviewer, in changed lines.
    for name, lines in sorted(_ai_hits(head.lines, added).items()):
        out.lines_check(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name}", path, lines)

    # Long lines and encoded blobs in changed lines.
    long_lines: list[int] = []
    blobs: dict[str, list[int]] = {}
    for n in added:
        line = head.lines[n - 1].rstrip("\r")
        if len(line) > LONG_LINE_CHARS:
            long_lines.append(n)
        if len(line) > BLOB_RUN_CHARS:
            for m in _B64_RUN_RE.finditer(line):
                kind = "hex" if _HEX_ONLY_RE.fullmatch(m.group()) else "base64"
                blobs.setdefault(kind, []).append(n)
            for m in _ESCAPED_RUN_RE.finditer(line):
                if len(m.group()) > BLOB_RUN_CHARS:
                    blobs.setdefault("escaped hex", []).append(n)

    # Base64 wrapped over consecutive lines. The run is measured over all head
    # lines, so changing one line inside a long blob still counts; it is
    # reported at the first changed line in the run.
    wrapped_run: list[int] = []
    wrapped_chars = 0

    def end_wrapped() -> None:
        nonlocal wrapped_chars
        if wrapped_chars > BLOB_RUN_CHARS and len(wrapped_run) > 1:
            changed_in_run = [n for n in wrapped_run if n in added_set]
            if changed_in_run:
                blobs.setdefault("base64 (wrapped)", []).append(changed_in_run[0])
        wrapped_run.clear()
        wrapped_chars = 0

    for n, raw in enumerate(head.lines, 1):
        line = raw.rstrip("\r")
        w = _WRAPPED_B64_LINE_RE.match(line) if len(line) >= 40 else None
        if w:
            wrapped_run.append(n)
            wrapped_chars += len(w.group(1))
        else:
            end_wrapped()
    end_wrapped()
    out.lines_check(LONG_LINE, SIGNAL, f"lines longer than {LONG_LINE_CHARS} characters", path, long_lines)
    for kind, lines in sorted(blobs.items()):
        out.lines_check(ENCODED_BLOB, SIGNAL, f"{kind} run longer than {BLOB_RUN_CHARS} characters", path, lines)


def _under_dist_or_build(path: str) -> bool:
    return any(part in ("dist", "build") for part in path.split("/")[:-1])


def _is_minified_js(path: str, head: _Lines) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(tuple(".min" + s for s in _JS_SUFFIXES)):
        return True
    text = head.text
    if any(marker in text for marker in _BUNDLE_MARKERS):
        return True
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return False
    longest = max(len(line) for line in lines)
    return longest > 5000 or (len(text) >= 1024 and len(text) / len(lines) > 250)


def _sensitive_path(path: str) -> str | None:
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    if low.startswith(".github/workflows/") or "/.github/workflows/" in low:
        return "workflow"
    if low.startswith(".github/actions/") or "/.github/actions/" in low:
        return "action"
    if name.startswith("dockerfile") or name.endswith(".dockerfile") or name.startswith("containerfile"):
        return "Dockerfile"
    if name in ("makefile", "gnumakefile"):
        return "Makefile"
    if name == ".npmrc":
        return ".npmrc"
    if name.startswith(".yarnrc"):
        return ".yarnrc"
    if name == "setup.py":
        return "setup.py"
    if name == "codeowners":
        return "CODEOWNERS"
    return None


def _strict_json(text: str) -> Any:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)

    return json.loads(text, object_pairs_hook=no_dupes)


def _install_scripts(text: str | None) -> dict[str, Any] | None:
    """Install lifecycle scripts of a package.json; None if it does not parse."""
    if text is None:
        return {}
    try:
        doc = _strict_json(text)
    except (ValueError, RecursionError):
        return None
    scripts = doc.get("scripts", {}) if isinstance(doc, dict) else None
    if not isinstance(scripts, dict):
        return None
    return {k: scripts[k] for k in _INSTALL_SCRIPTS if k in scripts}


def _build_system(text: str | None) -> Any:
    """The `[build-system]` table, or a sentinel string if it does not parse."""
    if text is None:
        return None
    try:
        return tomllib.loads(text).get("build-system")
    except (tomllib.TOMLDecodeError, RecursionError):
        return "<unparseable>"


def _check_file(
    out: _Results, change: ChangedFile, base: BlobScan | None, head: BlobScan | None,
    run: DiffBudget | None = None,
) -> None:
    path = change.path
    paths = [p for p in (change.path, change.old_path) if p]

    for p in paths:
        bidi = _BIDI_RE.findall(p)
        if bidi:
            out.add(BIDI_PATH, HARD_BLOCK, f"bidi control characters {_codepoints(bidi)} in path", file=p)
    path_hits = {name for p in paths for name in _ai_hits([p])}
    for name in sorted(path_hits):
        out.add(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name} in path", file=path)

    kinds = sorted({k for p in paths if (k := _sensitive_path(p))})
    if kinds:
        out.add(SENSITIVE_PATH, SIGNAL, f"change to {', '.join(kinds)}", file=path)
    if any(deps.is_unsupported_dep_file(p) or p.rsplit("/", 1)[-1].lower() in _EXTRA_UNSUPPORTED_DEP_FILES for p in paths):
        out.add(UNSUPPORTED_DEP_FILE, SIGNAL, "dependency file of an unsupported ecosystem changed", file=path)

    # Each side is a gitlink or a blob by its own mode. A blob side is checked
    # like any file, even when the other side is a gitlink.
    base_link = change.base_mode == MODE_SUBMODULE
    head_link = change.head_mode == MODE_SUBMODULE
    if base_link or head_link:
        if base_link and head_link:
            detail = "submodule commit changed"
        elif head_link:
            detail = "submodule added" if change.base_sha is None else "file replaced by a submodule"
        else:
            detail = "submodule removed" if change.head_sha is None else "submodule replaced by a file"
        old = change.base_sha if base_link else ("(file)" if change.base_sha else "(none)")
        new = change.head_sha if head_link else ("(file)" if change.head_sha else "(none)")
        out.add(SUBMODULE, SIGNAL, detail, file=path, subject=f"{old} -> {new}")
    if change.became_executable:
        out.add(EXECUTABLE, SIGNAL, f"mode {change.base_mode or '(new)'} -> {change.head_mode}", file=path)
    if (
        head is not None and head.kind == "binary" and not head_link
        and (base is None or base_link or base.kind != "binary")
    ):
        out.add(BINARY_ADDED, SIGNAL, "binary file added" if base is None else "file became binary", file=path)

    head_text = head.text if head is not None and head.kind == "full" else None
    base_text = base.text if base is not None and base.kind == "full" else None
    name = path.rsplit("/", 1)[-1]

    if head_text is not None or base_text is not None:
        if name == "package.json" and change.head_mode != MODE_SYMLINK:
            old, new = _install_scripts(base_text), _install_scripts(head_text)
            if new is None:
                out.add(INSTALL_SCRIPT_CHANGE, SIGNAL, "package.json does not parse; install scripts unknown", file=path)
            elif old != new:
                keys = sorted(k for k in set(old or {}) | set(new) if (old or {}).get(k) != new.get(k))
                out.add(INSTALL_SCRIPT_CHANGE, SIGNAL, f"install scripts changed: {', '.join(keys)}", file=path)
        if name == "pyproject.toml" and change.head_mode != MODE_SYMLINK:
            if _build_system(base_text) != _build_system(head_text):
                out.add(BUILD_SYSTEM_CHANGE, SIGNAL, "[build-system] changed", file=path)

    if head_text is None:
        return
    head_lines = _Lines(head_text)
    base_lines = _Lines(base_text) if base_text is not None else None
    added = _added_lines(head_lines, base_lines, run=run, path=path)
    _check_text(out, path, head_lines, added)
    if (
        path.lower().endswith(_JS_SUFFIXES)
        and not _under_dist_or_build(path)
        and change.head_mode != MODE_SYMLINK
        and _is_minified_js(path, head_lines)
    ):
        out.add(MINIFIED_JS, SIGNAL, "minified or bundled JavaScript outside dist/ and build/", file=path)


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

_OFFICIAL_HOSTS = {"npm": deps.NPM_OFFICIAL_HOSTS, "pypi": deps.PYPI_OFFICIAL_HOSTS}
_NPM_FAMILIES = frozenset({"package.json", *deps.MANIFEST_LOCKFILES["package.json"]})
_EXACT_VERSION_RE = re.compile(r"[A-Za-z0-9.+_-]+", re.ASCII)
# One exact semver version in package.json, with npm's optional `=` or `v`.
_NPM_EXACT_RE = re.compile(
    r"\s*=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\s*", re.ASCII
)


def _is_foreign(ecosystem: str, source: deps.Source) -> bool:
    """deps.Source.foreign, re-checked: an official source must name an
    official host of its own ecosystem."""
    if source.foreign:
        return True
    if source.kind == "registry":
        return source.host not in _OFFICIAL_HOSTS.get(ecosystem, frozenset())
    return False


def _exact_npm_spec(spec: str) -> tuple[str | None, str] | None:
    """(alias target or None, version) when a package.json value names one
    exact version: `1.2.3`, `=1.2.3`, `v1.2.3` or `npm:name@1.2.3`."""
    target = None
    if spec.strip().lower().startswith("npm:"):
        target, _, spec = spec.strip()[4:].rpartition("@")
        if not target:
            return None
    m = _NPM_EXACT_RE.fullmatch(spec)
    return (target, m.group(1)) if m else None


def _exact_pypi_spec(spec: str) -> str | None:
    """The version a PyPI specifier pins: a bare version (deps.py strips a lone
    `==`; Poetry reads a bare version as exact), or an `==`/`===` clause."""
    if _EXACT_VERSION_RE.fullmatch(spec) and any(ch.isdigit() for ch in spec):
        return spec
    for clause in spec.split(","):
        clause = clause.strip()
        if clause.startswith("==="):
            return clause[3:].strip() or None
        if clause.startswith("==") and "*" not in clause:
            return clause[2:].strip() or None
    return None


def registry_key(change: deps.PackageChange) -> tuple[str, str, str] | None:
    """(ecosystem, name, version) collect must look up, or None.

    The 72-hour rule applies to every new or changed exact version from the
    official registry: every lockfile entry, and every manifest or
    requirements entry that names one exact version, including an npm alias
    to another package. A range names no version, so it has no key.
    `DependencyFacts.registry` is keyed by this value.
    """
    if change.source.kind != "registry" or _is_foreign(change.ecosystem, change.source):
        return None
    family = deps.family_for_path(change.path)
    if family in deps.LOCKFILE_FAMILIES:
        return (change.ecosystem, change.name, change.new_version)
    if family == "package.json":
        exact = _exact_npm_spec(change.new_version)
        if exact is None:
            return None
        target, version = exact
        return ("npm", target or change.name, version)
    if family in ("pyproject.toml", "requirements"):
        version = _exact_pypi_spec(change.new_version)
        return ("pypi", change.name, version) if version else None
    return None


def needs_registry_lookup(change: deps.PackageChange) -> bool:
    """True when the 72-hour rule applies, so collect must look the version up."""
    return registry_key(change) is not None


def _check_deps(
    out: _Results,
    facts: DependencyFacts | None,
    changed: Sequence[ChangedFile],
    head_paths: frozenset[str],
    now: datetime,
) -> None:
    facts = facts or DependencyFacts()
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    for f in sorted(facts.failures, key=lambda f: (f.path, f.reason)):
        out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, f"dependency data incomplete: {f.reason}", file=f.path)
    failed = {f.path for f in facts.failures}
    for f in sorted(facts.base_failures, key=lambda f: (f.path, f.reason)):
        out.add(BASE_DEP_UNPARSED, SIGNAL, f"base side counts as empty: {f.reason}", file=f.path)
    for c in changed:
        # A gitlink head has no file to parse; a file head does, whatever the base was.
        if c.head_sha is None or c.head_mode == MODE_SUBMODULE or deps.family_for_path(c.path) is None:
            continue
        if c.path not in facts.parsed_paths and c.path not in failed:
            out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "supported dependency file was not parsed", file=c.path)

    for issue in facts.new_global_sources:
        eco = "npm" if deps.family_for_path(issue.path) in _NPM_FAMILIES else "pypi"
        if _is_foreign(eco, issue.source):
            out.add(
                FOREIGN_SOURCE, HARD_BLOCK, f"file-wide {issue.source.kind} source is not the official registry",
                file=issue.path, subject=issue.source.normalized,
            )

    for c in facts.changes:
        subject = f"{c.name}@{c.new_version}"
        if _is_foreign(c.ecosystem, c.source):
            out.add(
                FOREIGN_SOURCE, HARD_BLOCK, f"{c.source.kind} source is not the official registry",
                file=c.path, subject=f"{subject} from {c.source.normalized}",
            )
            continue
        key = registry_key(c)
        info = facts.registry.get(key) if key is not None else None
        if key is not None:
            if info is None:
                out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "no registry data for a new version", file=c.path, subject=subject)
            elif info.published.tzinfo is None:
                out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "registry publish time has no time zone", file=c.path, subject=subject)
            elif now - info.published < FRESH_PUBLISH_WINDOW:
                hours = (now - info.published).total_seconds() / 3600
                out.add(
                    FRESH_PUBLISH, HARD_BLOCK, f"published {hours:.1f} hours ago (under 72)",
                    file=c.path, subject=subject,
                )
        if c.ecosystem == "npm":
            if c.has_install_script:
                out.add(INSTALL_SCRIPT_DEP, SIGNAL, "lockfile entry has an install script", file=c.path, subject=subject)
            scripts = info.install_scripts if info is not None else {}
            if scripts and c.direct is not False:
                out.add(
                    INSTALL_SCRIPT_DEP, SIGNAL,
                    f"registry manifest has install scripts: {', '.join(sorted(scripts))}",
                    file=c.path, subject=subject,
                )
        if c.ecosystem == "pypi" and info is not None and info.has_wheel is False:
            out.add(SDIST_ONLY, SIGNAL, "no wheel; setup.py runs at install", file=c.path, subject=subject)

    changed_paths = [c.path for c in changed]
    for p in deps.manifest_without_lockfile(changed_paths, head_paths):
        out.add(MANIFEST_WITHOUT_LOCKFILE, SIGNAL, "manifest changed but its lockfile did not", file=p)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_FIRST_TIME = frozenset({"FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE"})


def run_prefilter(
    diff: TreeDiff,
    blobs: Mapping[str, bytes | None],
    *,
    head_paths: Iterable[str],
    now: datetime,
    dependencies: DependencyFacts | None = None,
    author_association: str | None = None,
    pr_title: str = "",
    pr_body: str = "",
    max_blob_bytes: int = MAX_BLOB_BYTES,
    unread_reasons: Mapping[str, str] | None = None,
    diff_budget: DiffBudget | None = None,
) -> PrefilterResult:
    """Run every prefilter check on one comparison.

    `blobs` maps a blob SHA to its bytes, or None when the read failed. A blob
    SHA missing from the map counts as unreadable. Each blob is checked against
    its SHA before it is scanned. `head_paths` is every path in the head tree.
    `unread_reasons` gives the coverage reason of a blob with no bytes when it
    is not `unreadable`, for example `over-cap` for a blob collect did not
    fetch because its tree size is over the cap. `diff_budget` is the run's
    line diff work (a fresh `DiffBudget` when None): every file takes from it.
    """
    unread_reasons = unread_reasons or {}
    diff_budget = DiffBudget() if diff_budget is None else diff_budget

    def scan(sha: str, path: str) -> BlobScan:
        data = blobs.get(sha)
        if data is None and sha in unread_reasons:
            return BlobScan("unavailable", reason=unread_reasons[sha])
        return scan_blob(data, sha=sha, cap=max_blob_bytes, path=path)

    out = _Results()
    file_cov: list[FileCoverage] = []
    collected = 0
    seen: set[str] = set()

    for change in diff.files:
        if change.path in seen:
            raise ValueError(f"duplicate path in diff: {change.path[:200]!r}")
        seen.add(change.path)
        # A gitlink side has no blob; its commit SHA is its content, so it
        # counts as binary. Every other side is read and scanned, so a gitlink
        # on one side never hides the blob on the other.
        base = head = None
        if change.base_sha is not None:
            base = (
                _GITLINK if change.base_mode == MODE_SUBMODULE
                else scan(change.base_sha, change.old_path or change.path)
            )
        if change.head_sha is not None:
            head = _GITLINK if change.head_mode == MODE_SUBMODULE else scan(change.head_sha, change.path)
        # Collected: every blob side was read and matches its SHA.
        read = [
            sha for sha, mode in ((change.base_sha, change.base_mode), (change.head_sha, change.head_mode))
            if sha is not None and mode != MODE_SUBMODULE
        ]
        if all(blobs.get(sha) is not None for sha in read) and all(
            s.reason != "sha-mismatch" for s in (base, head) if s is not None
        ):
            collected += 1
        cov = _file_coverage(change, base, head)
        # Ruling R-KEYBLOCK: a private key block with no END, or one that
        # holds text that is not key material, can hide code from Claude.
        # Fail closed.
        if cov.coverage != "unavailable" and any(
            s is not None and s.kind == "full" and render.unterminated_private_keys(s.text) for s in (base, head)
        ):
            cov = FileCoverage(change.path, "unavailable", "unterminated-private-key")
        file_cov.append(cov)
        _check_file(out, change, base, head, diff_budget)

    coverage = Coverage(
        trees_complete=diff.complete,
        files_in_comparison=len(diff.files),
        files_collected=collected,
        files=tuple(file_cov),
    )
    if not diff.complete:
        out.add(INCOMPLETE_COVERAGE, HARD_BLOCK, "a git tree was truncated; the comparison is incomplete")
    for fc in file_cov:
        if fc.coverage == "unavailable":
            out.add(INCOMPLETE_COVERAGE, HARD_BLOCK, f"file content not scanned: {fc.reason}", file=fc.path)

    _check_deps(out, dependencies, diff.files, frozenset(head_paths), now)

    for where, text in (("PR title", pr_title), ("PR body", pr_body)):
        hits = _ai_hits(text.split("\n"))
        for name, lines in sorted(hits.items()):
            out.add(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name} in {where}", lines=lines, count=len(lines))

    if author_association in _FIRST_TIME:
        out.add(FIRST_TIME_AUTHOR, SIGNAL, f"author_association {author_association} (context only)")

    return PrefilterResult(
        signals=tuple(c for c in out.items if c.level == SIGNAL),
        hard_blocks=tuple(c for c in out.items if c.level == HARD_BLOCK),
        coverage=coverage,
    )
