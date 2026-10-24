"""Import any SARIF 2.1.0 report (CodeQL, Bandit, ESLint, gosec, Snyk, Grype...).

This is import-only: triagegate does not run the tool, but its results go through the same
dedupe, scoring, policy and reporting as built-in scanners.
"""

from __future__ import annotations

from typing import Any, ClassVar

from triagegate.models import Category, Confidence, Finding, Location, Severity
from triagegate.scanners._util import first_sentence, read_snippet
from triagegate.scanners.base import ScanContext, Scanner, Step, as_list

_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _from_security_severity(value: Any) -> Severity | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def _category(tags: list[str]) -> Category:
    joined = " ".join(t.lower() for t in tags)
    if "secret" in joined:
        return Category.SECRETS
    if any(k in joined for k in ("dependency", "vulnerable-component", "sca", "cve")):
        return Category.SCA
    if any(k in joined for k in ("iac", "terraform", "kubernetes", "cloudformation")):
        return Category.IAC
    return Category.SAST


class SarifImporter(Scanner):
    name: ClassVar[str] = "sarif"
    binary: ClassVar[str] = ""

    def enabled(self, config: Any) -> bool:
        return False  # never runs on its own

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        return []

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for run in raw.get("runs") or []:
            driver = (run.get("tool") or {}).get("driver") or {}
            tool = str(driver.get("name") or "sarif").lower().replace(" ", "-")
            rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
            for res in run.get("results") or []:
                rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
                rule = rules.get(rule_id, {})
                props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
                tags = [str(t) for t in as_list(props.get("tags"))]
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
                severity = _from_security_severity(props.get("security-severity")) or _LEVEL.get(
                    str(level), Severity.MEDIUM
                )
                message = (res.get("message") or {}).get("text") or rule_id
                loc = (as_list(res.get("locations")) or [{}])[0].get("physicalLocation") or {}
                path = (loc.get("artifactLocation") or {}).get("uri", "")
                region = loc.get("region") or {}
                start, end = region.get("startLine"), region.get("endLine")
                snippet = (region.get("snippet") or {}).get("text") or read_snippet(
                    ctx.target, path, start, end
                )
                help_uri = rule.get("helpUri")
                findings.append(
                    Finding(
                        tool=tool,
                        rule_id=str(rule_id),
                        title=first_sentence(
                            (rule.get("shortDescription") or {}).get("text") or message
                        ),
                        description=message,
                        severity=severity,
                        category=_category(tags),
                        confidence=Confidence.MEDIUM,
                        location=Location(
                            path=path, start_line=start, end_line=end, snippet=snippet
                        ),
                        cwe=[t for t in tags if "cwe" in t.lower()],
                        references=[help_uri] if help_uri else [],
                        remediation=(rule.get("help") or {}).get("text"),
                    )
                )
        return findings
