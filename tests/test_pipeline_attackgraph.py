"""The attack graph runs inside the scan pipeline and feeds the gate."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.models import Category, Confidence, Finding, Location, Severity, ToolRun, ToolStatus
from breachgraph.pipeline import ScanOptions, process

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def code_finding(line: int, cwe: str, title: str) -> Finding:
    return Finding(
        tool="semgrep",
        rule_id=title.lower().replace(" ", "-"),
        title=title,
        severity=Severity.HIGH,
        category=Category.SAST,
        confidence=Confidence.HIGH,
        cwe=[cwe],
        location=Location(path="services/api/app.py", start_line=line),
    )


SSRF = code_finding(23, "CWE-918", "SSRF")
CMDI = code_finding(30, "CWE-78", "Command injection")
TOOLS = [ToolRun(name="semgrep", status=ToolStatus.IMPORTED, findings=2)]


def run(findings: list[Finding], config: Config | None = None, **opts: object):  # type: ignore[no-untyped-def]
    return process(
        findings,
        TOOLS,
        config or Config(),
        PLATFORM,
        ScanOptions(offline=True, **opts),  # type: ignore[arg-type]
    )


def test_attack_path_fails_the_gate() -> None:
    res = run([SSRF, CMDI])
    assert res.attack_graph is not None
    assert not res.gate.passed
    assert any("attack path" in r for r in res.gate.reasons)
    assert len(res.attack_graph.gating_paths) == 2


def test_no_vulns_no_gating_path() -> None:
    res = run([])
    assert res.attack_graph is not None
    assert not any("customer-data" in p.target for p in res.attack_graph.paths)


def test_can_be_disabled() -> None:
    cfg = Config.model_validate({"attack_graph": {"enabled": False}})
    res = run([SSRF, CMDI], cfg)
    assert res.attack_graph is None


def test_report_only_mode_does_not_gate_on_paths() -> None:
    cfg = Config.model_validate({"attack_graph": {"fail_on_new_path": False}})
    res = run([SSRF, CMDI], cfg)
    assert res.attack_graph is not None and res.attack_graph.paths
    assert not any("attack path" in r for r in res.gate.reasons)


def test_min_confidence_filters_gating() -> None:
    # Require high confidence only (default medium). Demo paths are high, so still gate.
    cfg = Config.model_validate({"attack_graph": {"min_confidence": "high"}})
    res = run([SSRF, CMDI], cfg)
    assert res.attack_graph is not None and res.attack_graph.gating_paths


def test_summary_round_trips_through_json() -> None:
    from breachgraph.models import ScanResult

    res = run([SSRF, CMDI])
    reloaded = ScanResult.model_validate_json(res.model_dump_json())
    assert reloaded.attack_graph is not None
    assert len(reloaded.attack_graph.paths) == len(res.attack_graph.paths)
    assert reloaded.attack_graph.choke_points[0].path == "services/api/app.py"
