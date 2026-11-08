"""A large repository is scanned in batches, and a timeout keeps what finished."""

import json
import sys
from pathlib import Path

import pytest

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


class Mixed(Slow):
    """Batches that finish or die, given as their exit codes."""

    codes: tuple[int, ...] = (0, 1, 0)

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        out = []
        for i, code in enumerate(self.codes):
            part = ctx.work_dir / f"{i}.json"
            script = f"import sys; open(sys.argv[1],'w').write('{{}}') if {code} == 0 else sys.exit({code})"
            out.append(Step([exe, "-c", script, str(part)], part))
        return out


def test_a_failed_batch_costs_that_batch_and_the_rest_still_run(tmp_path: Path) -> None:
    outcome = Mixed().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=Config()))
    assert outcome.run.status is ToolStatus.PARTIAL
    assert "1 of 3 batches failed" in (outcome.run.message or "")


def test_every_batch_failing_is_a_failure(tmp_path: Path) -> None:
    class AllBad(Mixed):
        codes = (1, 1)

    outcome = AllBad().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=Config()))
    assert outcome.run.status is ToolStatus.FAILED


def test_report_status_round_trips() -> None:
    assert json.dumps(ToolStatus.PARTIAL.value) == '"partial"'


def test_compatibility_rules_are_not_findings(tmp_path: Path) -> None:
    raw = {
        "results": [
            {
                "check_id": "python.lang.compatibility.python37.python37-compatibility-importlib2",
                "path": "a.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "needs 3.7", "severity": "ERROR", "metadata": {}},
            }
        ]
    }
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    assert SemgrepScanner().parse(raw, ctx) == []


@pytest.mark.parametrize(
    "path",
    ["scripts/gen.py", "app/foo.test.ts", "electron/ipc.node-test.mjs", "browser-tests/a.cjs", "public/w.js"],
)
def test_a_parameter_rule_means_nothing_where_no_request_arrives(tmp_path: Path, path: str) -> None:
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    result = {
        "check_id": "breachgraph.python.ssrf-parameter",
        "path": path,
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"message": "m", "severity": "WARNING", "metadata": {}},
    }
    assert SemgrepScanner().parse({"results": [result]}, ctx) == []
    result["path"] = "src/tools/fetch.py"
    assert len(SemgrepScanner().parse({"results": [result]}, ctx)) == 1


def test_a_tainted_match_replaces_the_parameter_match(tmp_path: Path) -> None:
    def hit(rule: str) -> dict[str, object]:
        return {
            "check_id": rule,
            "path": "a.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {"message": "m", "severity": "ERROR", "metadata": {}},
        }

    raw = {"results": [hit("breachgraph.python.ssrf-parameter"), hit("breachgraph.python.ssrf-tainted")]}
    ctx = ScanContext(target=tmp_path, work_dir=tmp_path, config=Config())
    assert [f.rule_id for f in SemgrepScanner().parse(raw, ctx)] == ["breachgraph.python.ssrf-tainted"]


def test_an_unreachable_registry_falls_back_to_our_rules(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from breachgraph.models import ToolRun
    from breachgraph.scanners import base

    seen: list[list[str]] = []

    def fake(self, ctx):  # type: ignore[no-untyped-def]
        seen.append(ctx.config.scanners.semgrep.config)
        status = ToolStatus.FAILED if len(seen) == 1 else ToolStatus.OK
        message = "Failed to download configuration from semgrep.dev" if len(seen) == 1 else None
        return base.ScannerOutcome(ToolRun(name="semgrep", status=status, message=message))

    monkeypatch.setattr(base.Scanner, "run", fake)
    config = Config.model_validate({"scanners": {"semgrep": {"config": ["breachgraph", "p/default"]}}})
    outcome = SemgrepScanner().run(ScanContext(target=tmp_path, work_dir=tmp_path, config=config))
    assert seen[1] == ["breachgraph"] and outcome.run.status is ToolStatus.PARTIAL
    assert "only breachgraph's own rules ran" in (outcome.run.message or "")


def test_the_bundled_rules_are_ours() -> None:
    import yaml

    from breachgraph.scanners.semgrep import bundled_rules

    files = list(Path(bundled_rules()).glob("*.yaml"))
    ids = [r["id"] for f in files for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]]
    assert len(ids) >= 25 and all(i.startswith("breachgraph.") for i in ids)
    assert all(
        r["metadata"]["cwe"] for f in files for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]
    )
