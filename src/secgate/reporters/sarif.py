"""SARIF 2.1.0 for GitHub code scanning (and any SARIF viewer).

Everything goes into a single run with driver "secgate": GitHub rejects uploads that contain
several runs for the same category, and one run keeps alerts stable across tool changes.
Rule ids are namespaced by tool ("semgrep/python.flask...", "trivy/CVE-2023-1234").
Findings that are not in the repository (DAST URLs, container images) are left out because
code scanning needs a file location; they stay in the JSON, HTML and Markdown reports.
"""

from __future__ import annotations

from typing import Any

from secgate import PROJECT_URL
from secgate.models import Finding, ScanResult, Severity, Status

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_id(f: Finding) -> str:
    return f"{f.tool}/{f.rule_id}"


def _message(f: Finding) -> str:
    lines = [
        f.title,
        "",
        f"Priority {f.priority.value} (risk {f.risk_score}/10): " + "; ".join(f.score_reasons),
    ]
    if len(f.sources) > 1:
        lines.append("Reported by: " + ", ".join(f.sources))
    if f.remediation:
        lines += ["", f.remediation]
    return "\n".join(lines)


def build(result: ScanResult) -> dict[str, Any]:
    findings = [f for f in result.findings if f.location.in_repo and f.location.path]
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rid = _rule_id(f)
        rule = rules.get(rid)
        if rule is None:
            rule = rules[rid] = {
                "id": rid,
                "name": f.rule_id,
                "shortDescription": {"text": f.title[:1000]},
                "fullDescription": {"text": (f.description or f.title)[:4000]},
                "help": {"text": f.remediation or f.title, "markdown": f.remediation or f.title},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {
                    "tags": [
                        "security",
                        f.category.value,
                        *f.cwe,
                        *(f"OWASP-{o}" for o in f.owasp),
                    ],
                    "security-severity": f"{f.risk_score:.1f}",
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[
                        f.confidence.value
                    ],
                },
            }
            if f.references:
                rule["helpUri"] = f.references[0]
        else:  # GitHub reads severity per rule; use the riskiest instance
            current = float(rule["properties"]["security-severity"])
            if f.risk_score > current:
                rule["properties"]["security-severity"] = f"{f.risk_score:.1f}"

    rule_index = {rid: i for i, rid in enumerate(rules)}
    results = []
    for f in findings:
        start = f.location.start_line or 1
        region: dict[str, Any] = {"startLine": start}
        if f.location.end_line and f.location.end_line >= start:
            region["endLine"] = f.location.end_line
        if f.location.snippet:
            region["snippet"] = {"text": f.location.snippet}
        res: dict[str, Any] = {
            "ruleId": _rule_id(f),
            "ruleIndex": rule_index[_rule_id(f)],
            "level": _LEVEL[f.severity],
            "message": {"text": _message(f)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.path, "uriBaseId": "%SRCROOT%"},
                        "region": region,
                    }
                }
            ],
            "partialFingerprints": {"secgateFingerprint/v1": f.fingerprint},
            "properties": {
                "priority": f.priority.value,
                "risk_score": f.risk_score,
                "sources": f.sources,
                "kev": f.enrichment.kev,
                "epss": f.enrichment.epss,
                "vuln_ids": f.vuln_ids,
            },
        }
        if result.baseline_used:
            res["baselineState"] = "unchanged" if f.status is Status.BASELINE else "new"
        if f.status is Status.SUPPRESSED:
            res["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f.suppression_reason or "",
                }
            ]
        results.append(res)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secgate",
                        "version": result.secgate_version,
                        "informationUri": PROJECT_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": all(
                            t.status.value != "failed" for t in result.tools
                        ),
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": w}} for w in result.warnings
                        ],
                    }
                ],
                "properties": {
                    "scanners": [t.model_dump(mode="json") for t in result.tools],
                },
            }
        ],
    }
