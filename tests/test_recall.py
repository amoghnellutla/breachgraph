"""The recall benchmark's scoring: a miss has to count as a miss."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
spec = importlib.util.spec_from_file_location("recall", ROOT / "benchmarks" / "recall.py")
assert spec and spec.loader
recall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recall)


def report(path: str, line: int, category: str = "sast") -> dict:  # type: ignore[type-arg]
    return {"findings": [{"category": category, "location": {"path": path, "start_line": line}}]}


LINES = {"src/app.py": [[100, 104]]}


def test_a_finding_on_the_fixed_lines_counts() -> None:
    assert recall.found(report("src/app.py", 102), LINES)
    assert recall.found(report("src/app.py", 96), LINES)  # the line before the fix's context


def test_a_finding_elsewhere_in_the_file_does_not() -> None:
    assert not recall.found(report("src/app.py", 300), LINES)


def test_another_file_does_not() -> None:
    assert not recall.found(report("src/other.py", 102), LINES)


def test_a_dependency_or_secret_on_that_line_is_not_finding_the_flaw() -> None:
    assert not recall.found(report("src/app.py", 102, "secrets"), LINES)


def test_the_tally_keeps_failed_scans_out_of_both_sides() -> None:
    rows = [
        {"weakness": "SSRF", "outcome": "ok", "found": True},
        {"weakness": "SSRF", "outcome": "ok", "found": False},
        {"weakness": "SQL injection", "outcome": "crash", "found": None},
    ]
    assert recall.tally(rows) == {"cases": 2, "found": 1, "by_weakness": {"SSRF": [1, 2]}}
