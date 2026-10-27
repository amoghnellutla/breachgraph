"""docs/benchmark.md must match the stored benchmark results and labels exactly."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location("bench_report", ROOT / "benchmarks" / "report.py")
assert spec and spec.loader
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


@pytest.mark.skipif(not (ROOT / "docs" / "benchmark.md").is_file(), reason="benchmark not published yet")
def test_published_benchmark_is_current_and_fully_labeled() -> None:
    rows = report.load()
    unlabeled = [(t["name"], k) for t, r, labels in rows for k in report.verdicts(r, labels)[1]]
    assert not unlabeled, f"label every reported path first: {unlabeled}"
    assert (ROOT / "docs" / "benchmark.md").read_text(encoding="utf-8") == report.render(rows), (
        "docs/benchmark.md is stale: run python benchmarks/report.py"
    )


def test_precision_counts_only_decided_paths() -> None:
    result = {"attack_paths": [{"key": "a", "confidence": "high"}, {"key": "b", "confidence": "low"}]}
    labels = {"paths": [{"key": "a", "verdict": "true"}, {"key": "b", "verdict": "unclear"}]}
    verdicts, missing = report.verdicts(result, labels)
    assert verdicts == {"a": "true", "b": "unclear"} and not missing
    assert report.verdicts(result, {})[1] == ["a", "b"]
