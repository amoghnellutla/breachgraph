"""docs/real-world.md must match its stored counts, name nobody, and stay inside the release limits."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location("corpus", ROOT / "benchmarks" / "corpus.py")
assert spec and spec.loader
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


def test_published_numbers_are_current_and_within_the_limits() -> None:
    c = json.loads(corpus.PUBLISHED.read_text(encoding="utf-8"))
    assert corpus.PAGE.read_text(encoding="utf-8") == corpus.render(c), (
        "docs/real-world.md is stale: run python benchmarks/corpus.py publish"
    )
    assert {k: c[k] for k in corpus.LIMITS if c[k] > corpus.LIMITS[k]} == {}
    assert c["real_gating_paths"] + c["false_gating_paths"] == c["gating_paths"]


def test_the_published_counts_cannot_carry_a_project_or_file_name() -> None:
    c = json.loads(corpus.PUBLISHED.read_text(encoding="utf-8"))
    assert not [v for k, v in c.items() if isinstance(v, str) and k not in ("date", "commit")]


def test_a_scan_that_saw_nothing_is_not_a_clean_result() -> None:
    project = {"name": "a/b", "deploy": ["helm"]}
    empty = {"tools": [], "findings": [], "attack_graph": {"coverage": {"routes": 0}}}
    assert corpus.measure(project, empty, 5.0)["outcome"] == "empty"
    routes = {"tools": [], "findings": [], "attack_graph": {"coverage": {"routes": 3}}}
    assert corpus.measure(project, routes, 5.0)["outcome"] == "ok"
