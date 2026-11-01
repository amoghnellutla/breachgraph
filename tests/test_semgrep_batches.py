"""A large repository is scanned in batches, and a timeout keeps what finished."""

import json
import sys
from pathlib import Path

from breachgraph.config import Config
from breachgraph.models import ToolStatus
from breachgraph.scanners.base import ScanContext, Step
from breachgraph.scanners.semgrep import BATCH, LARGE_REPO, SemgrepScanner, batches


def test_a_small_repository_is_one_run() -> None:
    assert batches(["a.py", "b/c.ts"]) == []


def test_a_large_repository_skips_tests_and_starts_with_the_server() -> None:
    files = [f"apps/web/components/c{i}.ts" for i in range(LARGE_REPO)]
    files += ["packages/core/run.ts", "src/routes/login.ts", "src/x.test.ts", "tests/a.ts", "lib.min.js"]
    groups = batches(files)
    flat = [f for g in groups for f in g]
    assert flat[:2] == ["packages/core/run.ts", "src/routes/login.ts"]
    assert not {"src/x.test.ts", "tests/a.ts", "lib.min.js"} & set(flat)
    assert max(len(g) for g in groups) <= BATCH


class Slow(SemgrepScanner):
    """Two quick batches, then one that outlasts the limit."""

    def executable(self) -> str:
        return sys.executable

    def version(self) -> str:
        return "1"

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        out = []
        for i, seconds in enumerate((0, 0, 30)):
            part = ctx.work_dir / f"{i}.json"
            code = f"import time,sys; time.sleep({seconds}); open(sys.argv[1],'w').write('{{}}')"
            out.append(Step([exe, "-c", code, str(part)], part))
        return out

    def parse(self, raw: object, ctx: ScanContext) -> list:  # type: ignore[type-arg]
        return []


def test_a_timeout_keeps_finished_batches(tmp_path: Path) -> None:
    config = Config.model_validate({"timeout": 4})
    outcome = Slow().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=config))
    assert outcome.run.status is ToolStatus.PARTIAL
    assert "after 2 of 3 batches" in (outcome.run.message or "")


def test_a_first_batch_timeout_is_a_failure(tmp_path: Path) -> None:
    class Stuck(Slow):
        def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
            return super().steps(ctx, exe)[2:]

    config = Config.model_validate({"timeout": 1})
    outcome = Stuck().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=config))
    assert outcome.run.status is ToolStatus.FAILED


def test_report_status_round_trips() -> None:
    assert json.dumps(ToolStatus.PARTIAL.value) == '"partial"'
