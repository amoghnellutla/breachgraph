"""A scanner's failure is readable, and a broken online audit doesn't lose zizmor's findings."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.models import ToolRun, ToolStatus
from breachgraph.scanners import base
from breachgraph.scanners.base import ScanContext, _reason
from breachgraph.scanners.zizmor import ZizmorScanner
from tests.test_entry_points import write


def test_a_stack_trace_becomes_one_line() -> None:
    trace = "thread 'main' at src/x.rs:1\n\x1b[31mError: request failed: 401 Bad credentials\x1b[0m\n  0: backtrace\n  1: more\n"
    assert _reason(trace) == "Error: request failed: 401 Bad credentials"
    assert _reason("") == "no output"


def test_zizmor_reruns_offline(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    write(tmp_path, ".github/workflows/a.yml", "on: push\njobs: {}\n")
    seen: list[list[str]] = []

    def fake(self, ctx):  # type: ignore[no-untyped-def]
        seen.append(ctx.config.scanners.zizmor.extra_args)
        failed = "--offline" not in seen[-1]
        status = ToolStatus.FAILED if failed else ToolStatus.OK
        return base.ScannerOutcome(ToolRun(name="zizmor", status=status))

    monkeypatch.setattr(base.Scanner, "run", fake)
    outcome = ZizmorScanner().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=Config()))
    assert outcome.run.status is ToolStatus.OK and "offline" in (outcome.run.message or "")
    assert seen == [[], ["--offline"]]
