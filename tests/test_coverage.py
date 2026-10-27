"""The coverage line: what the attack graph modeled, and why a result may be incomplete."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.models import ToolRun, ToolStatus
from breachgraph.pipeline import ScanOptions, process
from breachgraph.reporters import markdown
from tests.test_pipeline_attackgraph import CMDI, PLATFORM, SSRF


def run(target: Path, tools: list[ToolRun], findings=()):  # type: ignore[no-untyped-def]
    return process(
        [f.model_copy(deep=True) for f in findings], tools, Config(), target, ScanOptions(offline=True)
    )


ALL = [ToolRun(name=n, status=ToolStatus.OK) for n in ("semgrep", "trivy", "gitleaks")]


def test_complete_when_everything_ran() -> None:
    res = run(PLATFORM, ALL, [SSRF, CMDI])
    cov = res.attack_graph.coverage  # type: ignore[union-attr]
    assert cov is not None and cov.complete, cov.gaps
    assert cov.routes >= 3 and cov.cloud_resources and cov.kubernetes_objects and cov.ci_jobs
    assert cov.line().endswith("No coverage gaps detected.")
    assert cov.line() in markdown.render(res)


def test_missing_scanner_makes_the_result_incomplete() -> None:
    tools = [
        ToolRun(name="semgrep", status=ToolStatus.SKIPPED),
        ToolRun(name="trivy", status=ToolStatus.FAILED),
        ToolRun(name="gitleaks", status=ToolStatus.OK),
    ]
    cov = run(PLATFORM, tools).attack_graph.coverage  # type: ignore[union-attr]
    assert cov is not None and not cov.complete
    assert cov.missing_scanners == ["semgrep", "trivy"]
    assert "semgrep not installed, so code weaknesses" in cov.line()
    assert "trivy failed" in cov.line()


def test_app_only_repository_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef home():\n    return 'hi'\n",
        encoding="utf-8",
    )
    cov = run(tmp_path, ALL).attack_graph.coverage  # type: ignore[union-attr]
    assert cov is not None and cov.routes == 1 and not cov.complete
    assert any("no deployment configuration" in g for g in cov.gaps)
    assert any("no crown-jewel asset" in g for g in cov.gaps)
