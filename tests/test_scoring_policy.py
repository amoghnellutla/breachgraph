from datetime import date
from pathlib import Path

import pytest

from breachgraph.config import Config, ConfigError, Suppression, load_config
from breachgraph.models import (
    Category,
    Confidence,
    Priority,
    ScanResult,
    Severity,
    Status,
    ToolRun,
    ToolStatus,
)
from breachgraph.normalize import finalize
from breachgraph.policy import (
    apply_baseline,
    apply_suppressions,
    drop_excluded,
    evaluate_gate,
    load_baseline,
    write_baseline,
)
from breachgraph.scoring import score_all
from tests.conftest import make_finding, make_vuln


def scored(*findings, config: Config | None = None):  # type: ignore[no-untyped-def]
    items = finalize(list(findings))
    score_all(items, config or Config())
    return items


# ------------------------------------------------------------------ scoring


def test_kev_forces_p1() -> None:
    f = make_vuln(severity=Severity.MEDIUM)
    f.enrichment.kev = True
    (out,) = scored(f)
    assert out.priority is Priority.P1
    assert any("KEV" in r for r in out.score_reasons)


def test_high_epss_raises_priority() -> None:
    low, high = make_vuln(cve="CVE-1"), make_vuln(cve="CVE-2", pkg="other")
    low.cvss = high.cvss = 7.5
    low.enrichment.epss, high.enrichment.epss = 0.001, 0.6
    by_cve = {f.rule_id: f for f in scored(low, high)}
    assert by_cve["CVE-2"].risk_score > by_cve["CVE-1"].risk_score
    assert by_cve["CVE-2"].priority is Priority.P1


def test_test_paths_are_deprioritized() -> None:
    prod, test = (
        make_finding(path="src/app.py"),
        make_finding(path="tests/test_app.py", snippet="x"),
    )
    by_path = {f.location.path: f for f in scored(prod, test)}
    assert by_path["tests/test_app.py"].risk_score < by_path["src/app.py"].risk_score


def test_low_confidence_penalty() -> None:
    sure, unsure = (
        make_finding(confidence=Confidence.HIGH),
        make_finding(confidence=Confidence.LOW, snippet="y"),
    )
    out = {f.confidence: f for f in scored(sure, unsure)}
    assert out[Confidence.LOW].risk_score < out[Confidence.HIGH].risk_score


def test_severity_override() -> None:
    cfg = Config.model_validate({"severity_overrides": [{"rule": "semgrep:rule.one", "severity": "low"}]})
    (out,) = scored(make_finding(), config=cfg)
    assert out.severity is Severity.LOW


def test_results_sorted_by_risk() -> None:
    out = scored(
        make_finding(severity=Severity.LOW, snippet="a"),
        make_finding(severity=Severity.CRITICAL, snippet="b"),
    )
    assert out[0].severity is Severity.CRITICAL


# ------------------------------------------------------------------ policy


def _result(findings, baseline_used: bool = False) -> ScanResult:  # type: ignore[no-untyped-def]
    return ScanResult(breachgraph_version="t", target=".", findings=findings, baseline_used=baseline_used)


def test_gate_fails_on_threshold_and_passes_below() -> None:
    cfg = Config()
    items = scored(make_finding(severity=Severity.CRITICAL))
    assert not evaluate_gate(_result(items), cfg).passed
    items = scored(make_finding(severity=Severity.LOW))
    assert evaluate_gate(_result(items), cfg).passed


def test_gate_secret_always_blocks() -> None:
    items = scored(
        make_finding(tool="gitleaks", category=Category.SECRETS, severity=Severity.LOW, path="tests/x.py")
    )
    gate = evaluate_gate(_result(items), Config())
    assert not gate.passed and items[0].gating


def test_baseline_only_new_findings_gate(tmp_path: Path) -> None:
    old = scored(make_finding(severity=Severity.CRITICAL, snippet="old()"))
    path = tmp_path / "baseline.json"
    write_baseline(_result(old), path)

    current = scored(
        make_finding(severity=Severity.CRITICAL, snippet="old()", line=99),  # moved, same code
        make_finding(severity=Severity.CRITICAL, snippet="new()"),
    )
    apply_baseline(current, load_baseline(path))
    statuses = sorted(f.status.value for f in current)
    assert statuses == ["baseline", "new"]
    gate = evaluate_gate(_result(current, baseline_used=True), Config())
    assert not gate.passed
    assert sum(f.gating for f in current) == 1


def test_new_only_false_gates_baseline_too() -> None:
    items = scored(make_finding(severity=Severity.CRITICAL))
    items[0].status = Status.BASELINE
    cfg = Config.model_validate({"fail_on": {"new_only": False}})
    assert not evaluate_gate(_result(items, baseline_used=True), cfg).passed
    assert evaluate_gate(_result(items, baseline_used=True), Config()).passed


def test_suppression_by_rule_and_path() -> None:
    cfg = Config(
        suppressions=[
            Suppression(rule="rule.one", path="legacy/**", reason="accepted", expires=date(2099, 1, 1))
        ]
    )
    items = scored(make_finding(path="legacy/a.py", snippet="1"), make_finding(path="src/a.py", snippet="2"))
    apply_suppressions(items, cfg)
    by_path = {f.location.path: f.status for f in items}
    assert by_path == {"legacy/a.py": Status.SUPPRESSED, "src/a.py": Status.NEW}


def test_expired_suppression_resurfaces_with_warning() -> None:
    cfg = Config(suppressions=[Suppression(vuln="CVE-2021-44228", reason="x", expires=date(2020, 1, 1))])
    items = scored(make_vuln())
    warnings = apply_suppressions(items, cfg, today=date(2026, 1, 1))
    assert items[0].status is Status.NEW
    assert "expired" in warnings[0]


def test_suppression_requires_expiry_by_default() -> None:
    with pytest.raises(ValueError, match="expires"):
        Config.model_validate({"suppressions": [{"rule": "x", "reason": "because"}]})
    Config.model_validate(
        {"require_suppression_expiry": False, "suppressions": [{"rule": "x", "reason": "ok"}]}
    )


def test_suppression_requires_reason_and_selector() -> None:
    with pytest.raises(ValueError):
        Suppression(reason="  ", rule="x")
    with pytest.raises(ValueError):
        Suppression(reason="ok")


def test_scanner_error_policy() -> None:
    result = _result([])
    result.tools = [ToolRun(name="trivy", status=ToolStatus.FAILED, message="boom")]
    assert evaluate_gate(result, Config()).passed
    cfg = Config.model_validate({"fail_on": {"scanner_errors": True}})
    assert not evaluate_gate(result, cfg).passed


def test_drop_excluded_keeps_non_repo_locations() -> None:
    items = finalize(
        [
            make_finding(path="node_modules/x/index.js"),
            make_finding(path="src/a.py", snippet="z"),
            make_finding(tool="zap", category=Category.DAST, path="https://x/node_modules/", in_repo=False),
        ]
    )
    kept = {f.location.path for f in drop_excluded(items, Config())}
    assert kept == {"src/a.py", "https://x/node_modules/"}


def test_load_config_rejects_unknown_keys(tmp_path: Path) -> None:
    p = tmp_path / ".breachgraph.yml"
    p.write_text("version: 1\nfail_on:\n  priorty: P1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="priorty"):
        load_config(p)


def test_load_config_empty_file(tmp_path: Path) -> None:
    p = tmp_path / ".breachgraph.yml"
    p.write_text("", encoding="utf-8")
    assert load_config(p).fail_on.priority is Priority.P2
