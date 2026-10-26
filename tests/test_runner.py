"""Scanner execution: command construction and how run() handles success, crashes and timeouts."""

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from breachgraph.config import Config
from breachgraph.models import ToolStatus
from breachgraph.pipeline import PipelineError, ScanOptions, scan, select_scanners
from breachgraph.scanners import SCANNERS, ScanContext
from tests.conftest import FIXTURES

DEMO = Path(__file__).parent.parent / "examples" / "vulnerable-app"


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    cfg = Config.model_validate({"exclude_paths": ["node_modules/", "examples/legacy/", "**/*.min.js"]})
    return ScanContext(target=DEMO, work_dir=tmp_path, config=cfg)


def flat(ctx: ScanContext, name: str) -> list[str]:
    return [arg for step in SCANNERS[name].steps(ctx, "/bin/tool") for arg in step.cmd]


def test_semgrep_command(ctx: ScanContext) -> None:
    cmd = flat(ctx, "semgrep")
    assert "--metrics=off" in cmd and cmd[-1] == "."
    assert cmd[cmd.index("--config") + 1] == "p/default"
    excludes = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--exclude"]
    assert "node_modules" in excludes and "examples/legacy" in excludes
    assert "**/*.min.js" not in excludes  # globs are filtered by breachgraph afterwards


def test_gitleaks_always_redacts(ctx: ScanContext) -> None:
    cmd = flat(ctx, "gitleaks")
    assert "--redact" in cmd and cmd[1] == "dir"
    ctx.config.scanners.gitleaks.scan_history = True
    assert flat(ctx, "gitleaks")[1] == "dir"  # demo dir is not a git repo root


def test_trivy_command_and_sbom(ctx: ScanContext) -> None:
    ctx.config.scanners.trivy.images = ["app:1"]
    steps = SCANNERS["trivy"].steps(ctx, "/bin/trivy")
    assert len(steps) == 3  # fs scan, SBOM, image
    assert steps[1].parse is False and "cyclonedx" in steps[1].cmd
    assert "sbom" in ctx.artifacts
    fs = steps[0].cmd
    skips = [fs[i + 1] for i, a in enumerate(fs) if a == "--skip-dirs"]
    assert "**/node_modules" in skips and "examples/legacy" in skips
    assert steps[2].cmd[-1] == "app:1"


def test_checkov_skips_secrets_when_gitleaks_on(ctx: ScanContext) -> None:
    cmd = flat(ctx, "checkov")
    assert "secrets" in cmd[cmd.index("--skip-framework") :]
    ctx.config.scanners.checkov.frameworks = ["terraform"]
    assert "--skip-framework" not in flat(ctx, "checkov")


def test_zap_runs_only_with_target(ctx: ScanContext) -> None:
    assert SCANNERS["zap"].steps(ctx, "docker") == []
    assert not SCANNERS["zap"].enabled(ctx.config)
    ctx.config.scanners.zap.enabled = True
    ctx.config.scanners.zap.target_url = "http://localhost:8080"
    cmd = flat(ctx, "zap")
    assert "zap-baseline.py" in cmd and "http://localhost:8080" in cmd


def fake_run(fixture: str | None, code: int = 0, stderr: str = ""):  # type: ignore[no-untyped-def]
    def _run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        if fixture and "--output" in cmd:
            out = Path(cmd[cmd.index("--output") + 1])
            shutil.copyfile(FIXTURES / fixture, out)
        return subprocess.CompletedProcess(cmd, code, stdout="", stderr=stderr)

    return _run


def test_run_success(ctx: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_SEMGREP_BIN", "/fake/semgrep")
    monkeypatch.setattr(subprocess, "run", fake_run("semgrep.json"))
    outcome = SCANNERS["semgrep"].run(ctx)
    assert outcome.run.status is ToolStatus.OK
    assert outcome.run.findings == len(outcome.findings) == 26


def test_run_crash_reports_stderr(ctx: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_SEMGREP_BIN", "/fake/semgrep")
    monkeypatch.setattr(subprocess, "run", fake_run(None, code=2, stderr="invalid rule config"))
    outcome = SCANNERS["semgrep"].run(ctx)
    assert outcome.run.status is ToolStatus.FAILED
    assert "invalid rule config" in (outcome.run.message or "")


def test_run_timeout(ctx: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_SEMGREP_BIN", "/fake/semgrep")

    def boom(cmd: list[str], **kw: Any) -> None:
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", boom)
    outcome = SCANNERS["semgrep"].run(ctx)
    assert outcome.run.status is ToolStatus.FAILED and "timed out" in (outcome.run.message or "")


def test_missing_binary_is_skipped(ctx: ScanContext, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BREACHGRAPH_GITLEAKS_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    outcome = SCANNERS["gitleaks"].run(ctx)
    assert outcome.run.status is ToolStatus.SKIPPED


def test_select_scanners() -> None:
    cfg = Config()
    assert select_scanners(cfg, ScanOptions()) == [
        "semgrep",
        "gitleaks",
        "trivy",
        "checkov",
        "zizmor",
        "cicd",
    ]
    assert select_scanners(cfg, ScanOptions(only=["trivy"])) == ["trivy"]
    assert "semgrep" not in select_scanners(cfg, ScanOptions(skip=["semgrep"]))
    assert "trivy" not in select_scanners(cfg, ScanOptions(imports=[("trivy", Path("x"))]))
    cfg.scanners.checkov.enabled = False
    assert "checkov" not in select_scanners(cfg, ScanOptions())
    assert select_scanners(cfg, ScanOptions(only=["checkov"])) == ["checkov"]  # --only forces it on
    with pytest.raises(PipelineError):
        select_scanners(cfg, ScanOptions(only=["nessus"]))


def test_scan_survives_adapter_bug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(self: object, ctx: ScanContext) -> None:
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(type(SCANNERS["checkov"]), "run", explode)
    result = scan(
        DEMO,
        Config(),
        ScanOptions(only=["checkov"], imports=[("semgrep", FIXTURES / "semgrep.json")], offline=True),
        tmp_path / "work",
    )
    tools = {t.name: t for t in result.tools}
    assert tools["checkov"].status is ToolStatus.FAILED
    assert tools["semgrep"].status is ToolStatus.IMPORTED
    assert result.findings  # other results still reported


def test_trivy_retries_offline_when_registry_rate_limits(
    ctx: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BREACHGRAPH_TRIVY_BIN", "/fake/trivy")
    ctx.config.scanners.trivy.sbom = False
    calls: list[list[str]] = []

    def run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        if "--output" not in cmd:  # version probe
            return subprocess.CompletedProcess(cmd, 0, stdout="Version: 0.75.0", stderr="")
        calls.append(cmd)
        if "--offline-scan" not in cmd:
            err = "FATAL remote Maven repository returned 429 Too Many Requests"
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=err)
        shutil.copyfile(FIXTURES / "trivy.json", Path(cmd[cmd.index("--output") + 1]))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    outcome = SCANNERS["trivy"].run(ctx)
    assert outcome.run.status is ToolStatus.OK
    assert "offline-scan" in (outcome.run.message or "")
    assert outcome.findings
    assert len(calls) == 2
    assert not ctx.config.scanners.trivy.offline_scan  # caller's config is untouched
