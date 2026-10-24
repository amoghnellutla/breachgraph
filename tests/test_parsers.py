"""Parser tests against real scanner output captured from examples/vulnerable-app
(trimmed: see tests/fixtures). ZAP and SARIF fixtures follow the tools' documented formats."""

import json
from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.models import Category, Confidence, Severity
from breachgraph.scanners import IMPORTERS, ScanContext
from breachgraph.scanners.base import load_json
from tests.conftest import FIXTURES

DEMO = Path(__file__).parent.parent / "examples" / "vulnerable-app"


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    return ScanContext(target=DEMO, work_dir=tmp_path, config=Config())


def parse(tool: str, fixture: str, ctx: ScanContext):  # type: ignore[no-untyped-def]
    return IMPORTERS[tool].parse(load_json(FIXTURES / fixture), ctx)


def test_semgrep(ctx: ScanContext) -> None:
    findings = parse("semgrep", "semgrep.json", ctx)
    assert len(findings) == 26
    sqli = [f for f in findings if "sql" in f.rule_id and f.location.start_line == 21]
    assert sqli and all(f.category is Category.SAST for f in sqli)
    # Semgrep returns "requires login" instead of code; we read the real line from disk.
    assert "SELECT * FROM users" in (sqli[0].location.snippet or "")
    cmd = next(f for f in findings if "subprocess" in f.rule_id)
    assert "CWE-78" in " ".join(cmd.cwe)
    assert cmd.owasp  # registry rules carry OWASP tags
    assert all(f.severity in Severity for f in findings)


def test_gitleaks_never_keeps_secret(ctx: ScanContext) -> None:
    findings = parse("gitleaks", "gitleaks.json", ctx)
    assert {f.rule_id for f in findings} == {"generic-api-key", "private-key"}
    key = next(f for f in findings if f.rule_id == "private-key")
    assert key.severity is Severity.CRITICAL and key.confidence is Confidence.HIGH
    assert key.category is Category.SECRETS and key.cwe == ["CWE-798"]
    settings = (DEMO / "settings.py").read_text(encoding="utf-8")
    real_value = settings.split('PAYMENTS_API_KEY = "')[1].split('"')[0]
    dumped = json.dumps([f.model_dump(mode="json") for f in findings])
    assert real_value not in dumped


def test_gitleaks_redacts_even_without_redact_flag(ctx: ScanContext) -> None:
    raw = [
        {
            "RuleID": "github-pat",
            "Description": "GitHub PAT",
            "File": "a.py",
            "StartLine": 1,
            "Secret": "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "Match": "t = ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
        }
    ]
    (f,) = IMPORTERS["gitleaks"].parse(raw, ctx)
    assert "ghp_" not in (f.location.snippet or "")
    assert f.severity is Severity.CRITICAL


def test_trivy(ctx: ScanContext) -> None:
    findings = parse("trivy", "trivy.json", ctx)
    sca = [f for f in findings if f.category is Category.SCA]
    iac = [f for f in findings if f.category is Category.IAC]
    assert len(sca) == 6 and iac
    log4shell = next(f for f in sca if f.rule_id == "CVE-2021-44228")
    assert log4shell.package is not None
    assert log4shell.package.name.endswith("log4j-core")
    assert log4shell.package.fixed_version
    assert log4shell.cvss and log4shell.cvss >= 9.0
    assert log4shell.location.path == "pom.xml"
    assert log4shell.location.start_line  # from --list-all-pkgs package locations
    assert log4shell.remediation and "Upgrade" in log4shell.remediation
    tf = [f for f in iac if f.location.path == "infra/main.tf"]
    assert tf and all(f.location.start_line for f in tf)
    assert all(f.rule_id for f in iac)


def test_checkov(ctx: ScanContext) -> None:
    findings = parse("checkov", "checkov.json", ctx)
    assert findings
    assert all(f.category is Category.IAC for f in findings)
    assert all(not f.location.path.startswith("/") for f in findings)
    assert {f.location.path for f in findings} >= {
        "Dockerfile",
        "infra/main.tf",
        "k8s/deployment.yaml",
    }
    assert all(f.location.start_line for f in findings)


def test_checkov_single_framework_and_empty(ctx: ScanContext) -> None:
    scanner = IMPORTERS["checkov"]
    assert scanner.parse({"passed": 0, "failed": 0, "skipped": 0}, ctx) == []
    one = load_json(FIXTURES / "checkov.json")[0]
    assert scanner.parse(one, ctx)


ZAP_REPORT = {
    "@version": "2.16.0",
    "site": [
        {
            "@name": "http://localhost:5000",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alertRef": "10038-1",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "cweid": "693",
                    "wascid": "15",
                    "desc": "<p>CSP is an added layer of security.</p>",
                    "solution": "<p>Set the CSP header.</p>",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>",
                    "instances": [
                        {
                            "uri": "http://localhost:5000/",
                            "method": "GET",
                            "param": "",
                            "evidence": "",
                        },
                        {
                            "uri": "http://localhost:5000/ping",
                            "method": "GET",
                            "param": "",
                            "evidence": "",
                        },
                    ],
                }
            ],
        }
    ],
}


def test_zap(ctx: ScanContext) -> None:
    findings = IMPORTERS["zap"].parse(ZAP_REPORT, ctx)
    assert len(findings) == 2
    f = findings[0]
    assert f.category is Category.DAST and f.severity is Severity.MEDIUM
    assert f.cwe == ["CWE-693"] and not f.location.in_repo
    assert f.description == "CSP is an added layer of security."
    assert f.references == ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]


SARIF_REPORT = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Bandit",
                    "rules": [
                        {
                            "id": "B602",
                            "shortDescription": {"text": "subprocess call with shell=True"},
                            "helpUri": "https://bandit.readthedocs.io/en/latest/plugins/b602.html",
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-78"],
                                "security-severity": "8.1",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "B602",
                    "level": "error",
                    "message": {"text": "subprocess call with shell=True identified"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 29},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_generic_sarif_import(ctx: ScanContext) -> None:
    (f,) = IMPORTERS["sarif"].parse(SARIF_REPORT, ctx)
    assert f.tool == "bandit" and f.rule_id == "B602"
    assert f.severity is Severity.HIGH  # from security-severity 8.1
    assert f.location.snippet and "check_output" in f.location.snippet  # read from disk
    assert f.cwe == ["external/cwe/cwe-78"]  # normalized later by finalize()


def test_parsers_tolerate_garbage(ctx: ScanContext) -> None:
    for name, scanner in IMPORTERS.items():
        assert scanner.parse(None, ctx) == [], name
        assert scanner.parse("not json", ctx) == [], name
