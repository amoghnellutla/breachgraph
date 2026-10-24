import json
import xml.etree.ElementTree as ET
from datetime import date

import jsonschema

from tests.conftest import FIXTURES, make_finding, make_vuln
from triagegate.config import Config, Suppression
from triagegate.models import Category, ScanResult, Status, ToolRun, ToolStatus
from triagegate.normalize import dedupe, finalize
from triagegate.policy import apply_suppressions, evaluate_gate
from triagegate.reporters import html, junit, markdown, sarif
from triagegate.scoring import score_all


def sample_result() -> ScanResult:
    findings = finalize(
        [
            make_finding(
                cwe=["CWE-89"], title="SQL injection via string concat", references=["https://x/y"]
            ),
            make_finding(
                tool="gitleaks",
                rule_id="generic-api-key",
                category=Category.SECRETS,
                title="Hardcoded secret: Generic API Key",
                path="settings.py",
                line=4,
                snippet="KEY = REDACTED",
            ),
            make_vuln(),
            make_finding(
                tool="zap",
                rule_id="10038",
                category=Category.DAST,
                title="CSP header not set",
                path="http://localhost:5000/",
                in_repo=False,
                line=None,
            ),
            make_finding(
                rule_id="rule.two",
                title="Ping @security-team <script>alert(1)</script> | pipe",
                snippet="x()",
                references=["javascript:alert(1)"],
            ),
        ]
    )
    next(f for f in findings if f.rule_id == "CVE-2021-44228").enrichment.kev = True
    items = dedupe(findings)
    config = Config(
        suppressions=[Suppression(rule="rule.two", reason="test only", expires=date(2099, 1, 1))]
    )
    score_all(items, config)
    apply_suppressions(items, config)
    result = ScanResult(
        triagegate_version="0.1.0",
        target="/repo",
        findings=items,
        tools=[
            ToolRun(name="semgrep", status=ToolStatus.OK, findings=2),
            ToolRun(name="checkov", status=ToolStatus.SKIPPED, message="not found"),
        ],
        warnings=["EPSS enrichment unavailable: offline"],
    )
    result.gate = evaluate_gate(result, config)
    return result


def test_sarif_validates_against_official_schema() -> None:
    doc = sarif.build(sample_result())
    schema = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    jsonschema.validate(doc, schema)


def test_sarif_content() -> None:
    doc = sarif.build(sample_result())
    run = doc["runs"][0]
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    }
    assert "http://localhost:5000/" not in uris  # DAST is excluded from code scanning
    assert "pom.xml" in uris
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "trivy/CVE-2021-44228" in rule_ids
    for r in run["tool"]["driver"]["rules"]:
        assert 0 <= float(r["properties"]["security-severity"]) <= 10
    suppressed = [r for r in run["results"] if "suppressions" in r]
    assert len(suppressed) == 1
    for r in run["results"]:
        assert r["partialFingerprints"]["triagegateFingerprint/v1"]
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_markdown_comment() -> None:
    result = sample_result()
    md = markdown.render(result, link_base="https://github.com/o/r/blob/abc")
    assert md.startswith(markdown.MARKER)
    assert "Security gate failed" in md
    assert "**KEV**" in md
    assert "https://github.com/o/r/blob/abc/app.py#L10" in md
    assert "@security-team" not in md  # mentions are defanged
    assert "\\|" in md or "pipe" not in md


def test_markdown_truncates_huge_reports() -> None:
    result = sample_result()
    result.findings = result.findings * 3000
    for f in result.findings:
        f.status = Status.NEW
    assert len(markdown.render(result)) < 65_536


def test_html_escapes_untrusted_content() -> None:
    page = html.render(sample_result())
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert 'href="javascript:' not in page
    assert "Gate failed" in page


def test_junit_marks_gating_findings_as_failures() -> None:
    root = ET.fromstring(junit.render(sample_result()))
    failures = sum(int(s.get("failures", 0)) for s in root.iter("testsuite"))
    assert failures >= 2  # KEV vuln + secret
    names = [c.get("name") for c in root.iter("testcase")]
    assert not any("rule.two" in (n or "") for n in names)  # suppressed findings are left out
