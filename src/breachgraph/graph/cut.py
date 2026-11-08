"""The fewest fixes that close every path.

A path breaks when any one of its weaknesses is fixed, so this is minimum hitting set. Fixing what
breaks the most paths first is the obvious answer and it isn't always the smallest one, so this
searches for the smallest, within a budget, starting from the obvious answer. Whatever it returns is
then checked against the paths from scratch, so a bug here can't report a set that leaves one open.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

SEARCH_BUDGET = 200_000


@dataclass
class FixSet:
    fixes: list[str]
    exact: bool  # proved smallest, not only small
    closes: int  # paths with a fix in the set
    beyond_code: int  # paths with no finding to fix: a setting has to change


def greedy(paths: Sequence[frozenset[str]]) -> list[str]:
    open_paths = list(paths)
    picks: list[str] = []
    while open_paths:
        counts = Counter(w for p in open_paths for w in p)
        best = min(counts, key=lambda w: (-counts[w], w))
        picks.append(best)
        open_paths = [p for p in open_paths if best not in p]
    return picks


def _smallest(paths: Sequence[frozenset[str]], bound: list[str]) -> tuple[list[str], bool]:
    best = list(bound)
    budget = SEARCH_BUDGET

    def search(remaining: list[frozenset[str]], chosen: list[str]) -> None:
        nonlocal best, budget
        budget -= 1
        if budget <= 0 or len(chosen) >= len(best):
            return
        if not remaining:
            best = list(chosen)
            return
        # Paths with nothing in common each need their own fix: stop if that can't beat the best.
        disjoint: list[frozenset[str]] = []
        for p in remaining:
            if all(not p & q for q in disjoint):
                disjoint.append(p)
        if len(chosen) + len(disjoint) >= len(best):
            return
        branch = min(remaining, key=len)  # the tightest path has the fewest ways to be closed
        for weakness in sorted(branch):
            search([p for p in remaining if weakness not in p], [*chosen, weakness])

    search(sorted(paths, key=len), [])
    return best, budget > 0


def smallest_fix_set(paths: Iterable[Iterable[str]]) -> FixSet:
    """The fewest weaknesses that touch every path. Paths with no weakness can't be counted."""
    every = [frozenset(p) for p in paths]
    fixable = list(dict.fromkeys(p for p in every if p))
    fixes, exact = _smallest(fixable, greedy(fixable))
    chosen = set(fixes)
    if any(not p & chosen for p in fixable):  # the proof: recomputed, not assumed
        fixes, exact = greedy(fixable), False
    closes = sum(1 for p in every if p & set(fixes))
    return FixSet(sorted(fixes), exact, closes, len(every) - closes)
