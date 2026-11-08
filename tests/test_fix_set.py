"""The smallest set of fixes: smaller than the obvious answer, and checked."""

import itertools
import random

from breachgraph.graph import cut
from breachgraph.graph.cut import greedy, smallest_fix_set


def test_the_most_popular_fix_is_not_always_in_the_smallest_set() -> None:
    # x touches four paths, so it goes first, and then two more are needed. a and b do it alone.
    paths = [{"a", "x", "p"}, {"a", "x", "q"}, {"a"}, {"b", "x", "r"}, {"b", "x", "s"}, {"b"}]
    assert len(greedy([frozenset(p) for p in paths])) == 3
    found = smallest_fix_set(paths)
    assert found.fixes == ["a", "b"] and found.exact


def brute(paths: list[frozenset[str]]) -> int:
    names = sorted({w for p in paths for w in p})
    for size in range(len(names) + 1):
        for combo in itertools.combinations(names, size):
            if all(p & set(combo) for p in paths):
                return size
    return 0


def test_it_matches_exhaustive_search() -> None:
    rng = random.Random(7)  # noqa: S311 - reproducible test cases, not secrets
    for _ in range(200):
        paths = [frozenset(rng.sample("abcdefgh", rng.randint(1, 3))) for _ in range(rng.randint(1, 9))]
        found = smallest_fix_set(paths)
        assert len(found.fixes) == brute(paths)
        assert all(p & set(found.fixes) for p in paths)


def test_a_path_with_no_finding_is_counted_apart() -> None:
    found = smallest_fix_set([{"a"}, set()])
    assert (found.fixes, found.closes, found.beyond_code) == (["a"], 1, 1)


def test_no_paths_no_fixes() -> None:
    assert smallest_fix_set([]).fixes == []


def test_out_of_budget_it_stays_valid_and_says_it_is_not_proved(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cut, "SEARCH_BUDGET", 1)
    paths = [{"a", "b"}, {"b", "c"}, {"c", "d"}, {"d", "e"}, {"e", "f"}]
    found = smallest_fix_set(paths)
    assert not found.exact
    assert all(set(p) & set(found.fixes) for p in paths)


def test_a_wrong_answer_cannot_get_out(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cut, "_smallest", lambda paths, bound: (["nothing"], True))
    found = smallest_fix_set([{"a"}, {"b"}])
    assert found.fixes == ["a", "b"] and not found.exact
