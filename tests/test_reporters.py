import json
import re
import xml.etree.ElementTree as ET
from datetime import date

import jsonschema

from breachgraph.config import Config, Suppression
from breachgraph.models import Category, ScanResult, Status, ToolRun, ToolStatus
from breachgraph.normalize import dedupe, finalize
from breachgraph.policy import apply_suppressions, evaluate_gate
from breachgraph.reporters import html, junit, markdown, sarif
from breachgraph.scoring import score_all
from tests.conftest import FIXTURES, make_finding, make_vuln


def sample_result() -> ScanResult:
    findings = finalize(
        [
            make_finding(cwe=["CWE-89"], title="SQL injection via string concat", references=["https://x/y"]),
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
    config = Config(suppressions=[Suppression(rule="rule.two", reason="test only", expires=date(2099, 1, 1))])
    score_all(items, config)
    apply_suppressions(items, config)
    result = ScanResult(
        breachgraph_version="0.1.0",
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
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]}
    assert "http://localhost:5000/" not in uris  # DAST is excluded from code scanning
    assert "pom.xml" in uris
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "trivy/CVE-2021-44228" in rule_ids
    for r in run["tool"]["driver"]["rules"]:
        assert 0 <= float(r["properties"]["security-severity"]) <= 10
    suppressed = [r for r in run["results"] if "suppressions" in r]
    assert len(suppressed) == 1
    for r in run["results"]:
        assert r["partialFingerprints"]["breachgraphFingerprint/v1"]
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


def _result_with_paths():
    from pathlib import Path

    from breachgraph.models import ToolRun, ToolStatus
    from breachgraph.pipeline import ScanOptions, process

    platform = Path(__file__).parent.parent / "examples" / "vulnerable-platform"
    findings = [
        make_finding(
            tool="semgrep",
            rule_id="ssrf",
            title="SSRF via requests.get",
            category=Category.SAST,
            cwe=["CWE-918"],
            path="services/api/app.py",
            line=23,
        ),
        make_finding(
            tool="semgrep",
            rule_id="cmdi",
            title="Command injection via os.popen",
            category=Category.SAST,
            cwe=["CWE-78"],
            path="services/api/app.py",
            line=30,
        ),
    ]
    return process(
        findings,
        [ToolRun(name="semgrep", status=ToolStatus.IMPORTED, findings=2)],
        Config(),
        platform,
        ScanOptions(offline=True),
    )


def test_markdown_shows_attack_paths() -> None:
    md = markdown.render(_result_with_paths())
    assert "Attack paths" in md
    assert "customer-data" in md
    assert "Fix these first" in md
    assert "code_execution" in md or "Command injection" in md


def test_html_shows_attack_paths() -> None:
    page = html.render(_result_with_paths())
    assert "Attack paths" in page
    assert "S3 bucket shop-customer-data-prod" in page
    assert "weapon" in page  # the flow diagram marks weapon hops
    assert "blocks merge" in page


def test_reporters_handle_missing_attack_graph() -> None:
    r = sample_result()  # has no attack_graph
    assert r.attack_graph is None
    assert "Attack paths" not in markdown.render(r)
    assert html.render(r)  # does not error


def test_ai_insights_render() -> None:
    from breachgraph.models import AIInsight, AIVerdict

    result = _result_with_paths()
    f = result.findings[0]
    f.gating = True
    f.ai = AIInsight(
        verdict=AIVerdict.LIKELY_FALSE_POSITIVE,
        summary="Real SSRF.",
        reasoning="User URL flows to requests.get.",
        remediation="Add an allowlist.",
        fix_code="if host not in ALLOWED:\n    abort(400)",
        model="claude-opus-5-5",
    )
    md = markdown.render(result)
    assert "🤖 likely false positive" in md
    assert "AI triage: verdicts and fixes (1)" in md
    assert "**Fix:** Add an allowlist." in md and "abort(400)" in md
    page = html.render(result)
    assert "AI triage: likely false positive" in page and "Add an allowlist" in page
    assert "abort(400)" in page and "Advisory only" in page


def test_ai_text_cannot_inject_markdown() -> None:
    from breachgraph.models import AIInsight, AIVerdict

    result = _result_with_paths()
    f = result.findings[0]
    f.gating = True
    f.ai = AIInsight(
        verdict=AIVerdict.TRUE_POSITIVE,
        summary="See ![x](https://evil.example/p.png) <img src=x> @org/team",
        reasoning="[click here](https://evil.example) <script>alert(1)</script>",
        remediation="**ok**",
        fix_code="print('```')\n```\n[link](https://evil.example)",
        model="m",
    )
    md = markdown.render(result)
    outside_code = md.split("````")[0]
    assert "![x](" not in outside_code and "](https://evil.example)" not in outside_code
    assert not re.search(r"(?<!\\)<(img|script)", md)  # tags are escaped, so they render as text
    assert "@​org" in md  # no mentions
    assert re.search(r"````\w*\nprint\('```'\)", md)  # fence is longer than any backtick run in the code
