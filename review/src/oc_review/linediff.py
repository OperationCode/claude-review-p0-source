"""Bounded line diff, shared by collect (patches) and publish (inline hunks).

The common prefix and suffix are trimmed first, so a small change to a large
file is cheap. The middle is diffed line by line (difflib) only within two
limits:

- a size budget: the product of the middle lengths;
- a work budget: counted steps of difflib's inner loop. On low-entropy input
  (few distinct lines, each repeated many times) that work grows about with
  the cube of the line count, so the size budget alone does not bound it.
  Each file gets at most `FILE_WORK_BUDGET` steps, and every file of one run
  shares one `WorkBudget` of `RUN_WORK_BUDGET` steps.

The count is deterministic (it depends on the input only, never on the
clock). Past a limit the middle is one `replace`: every base line there is
removed and every head line added. The result then is not exact, and its
`reason` names the limit.
"""

from __future__ import annotations

import difflib
from bisect import bisect_left
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

Opcode = tuple[str, int, int, int, int]

# Past this product of middle lengths, the middle is not diffed line by line.
DIFF_BUDGET = 25_000_000
# Counted steps (see `_CountingMatcher`) for one file, and for all files of one
# run. Measured on an Apple M-series core: 15 to 40 million steps per second,
# so at most about 0.35 s per file and 7 s per run (spec "Coverage limits").
FILE_WORK_BUDGET = 5_000_000
RUN_WORK_BUDGET = 100_000_000

PAST_SIZE_BUDGET = "line diff past the size budget"
PAST_FILE_WORK_BUDGET = "line diff past the per-file work budget"
PAST_RUN_WORK_BUDGET = "line diff past the run work budget"


class WorkBudget:
    """Diff work left for one run. Every file of the run takes from it."""

    def __init__(self, total: int | None = None, per_file: int | None = None) -> None:
        self.left = RUN_WORK_BUDGET if total is None else total
        self.per_file = FILE_WORK_BUDGET if per_file is None else per_file


@dataclass(frozen=True)
class Diff:
    """Opcodes of `a` to `b`. `reason` is None when they are exact."""

    codes: list[Opcode]
    reason: str | None = None

    @property
    def exact(self) -> bool:
        return self.reason is None


class _Spent(Exception):
    pass


class _CountingMatcher(difflib.SequenceMatcher):
    """SequenceMatcher (no junk) that stops when its step allowance is spent.

    Steps: one per line of both sequences (building the index), and for each
    `find_longest_match` call one per line of both ranges plus one per inner
    loop pass (each `j` that `a[i]` matches below `bhi`, and the pass that
    ends the `j` loop). This is at least the work difflib does, so time is
    about proportional to the count. A call is counted before it runs.
    """

    def __init__(self, a: Sequence[Any], b: Sequence[Any], allowance: int) -> None:
        self.left = allowance - len(a) - len(b)
        if self.left < 0:
            raise _Spent
        super().__init__(None, a, b, autojunk=False)

    def find_longest_match(self, alo: int = 0, ahi: int | None = None, blo: int = 0, bhi: int | None = None):
        ahi = len(self.a) if ahi is None else ahi
        bhi = len(self.b) if bhi is None else bhi
        left = self.left - (ahi - alo) - (bhi - blo)
        b2j, a = self.b2j, self.a
        for i in range(alo, ahi):
            js = b2j.get(a[i])
            if js:
                left -= bisect_left(js, bhi) + 1
                if left < 0:
                    raise _Spent
        if left < 0:
            raise _Spent
        self.left = left
        return super().find_longest_match(alo, ahi, blo, bhi)


def diff(a: Sequence[Any], b: Sequence[Any], budget: int = DIFF_BUDGET, work: WorkBudget | None = None) -> Diff:
    """difflib-style opcodes of `a` to `b`, bounded by the size budget and by
    `work` (a fresh `WorkBudget` when None)."""
    if work is None:
        work = WorkBudget()
    pre = 0
    while pre < len(a) and pre < len(b) and a[pre] == b[pre]:
        pre += 1
    suf = 0
    while suf < len(a) - pre and suf < len(b) - pre and a[-1 - suf] == b[-1 - suf]:
        suf += 1
    am, bm = a[pre : len(a) - suf], b[pre : len(b) - suf]
    codes: list[Opcode] = []
    reason: str | None = None
    if pre:
        codes.append(("equal", 0, pre, 0, pre))
    if am or bm:
        middle: list[Opcode]
        if not am:
            middle = [("insert", 0, 0, 0, len(bm))]
        elif not bm:
            middle = [("delete", 0, len(am), 0, 0)]
        elif len(am) * len(bm) > budget:
            reason = PAST_SIZE_BUDGET
        else:
            allowance = max(0, min(work.per_file, work.left))
            try:
                matcher = _CountingMatcher(am, bm, allowance)
                middle = matcher.get_opcodes()
            except _Spent:
                # Charge the whole allowance: the count that was cut off ran in part.
                work.left -= allowance
                reason = PAST_FILE_WORK_BUDGET if allowance == work.per_file else PAST_RUN_WORK_BUDGET
            else:
                work.left -= allowance - matcher.left
        if reason is not None:
            middle = [("replace", 0, len(am), 0, len(bm))]
        codes.extend((tag, i1 + pre, i2 + pre, j1 + pre, j2 + pre) for tag, i1, i2, j1, j2 in middle)
    if suf:
        codes.append(("equal", len(a) - suf, len(a), len(b) - suf, len(b)))
    return Diff(codes, reason)


def hunks(codes: list[Opcode], n: int) -> Iterator[list[Opcode]]:
    """Group opcodes into hunks with `n` lines of context (difflib's rule)."""
    if not any(tag != "equal" for tag, *_ in codes):
        return
    codes = list(codes)
    tag, i1, i2, j1, j2 = codes[0]
    if tag == "equal":
        codes[0] = (tag, max(i1, i2 - n), i2, max(j1, j2 - n), j2)
    tag, i1, i2, j1, j2 = codes[-1]
    if tag == "equal":
        codes[-1] = (tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n))
    group: list[Opcode] = []
    for tag, i1, i2, j1, j2 in codes:
        if tag == "equal" and i2 - i1 > 2 * n:
            group.append((tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)))
            yield group
            group = []
            i1, j1 = max(i1, i2 - n), max(j1, j2 - n)
        group.append((tag, i1, i2, j1, j2))
    if group and not (len(group) == 1 and group[0][0] == "equal"):
        yield group
