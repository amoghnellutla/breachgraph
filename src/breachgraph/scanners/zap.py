"""Import an OWASP ZAP JSON report (``breachgraph scan --import zap=zap.json``).

This is import-only. Scanning a running application is a different job from gating a change, so
ZAP runs in its own step (for example zaproxy/action-baseline) and breachgraph merges its alerts
into the same dedupe, scoring and reports.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.scanners.base import ScanContext, Scanner, Step

_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_CONF = {"4": Confidence.HIGH, "3": Confidence.HIGH, "2": Confidence.MEDIUM, "1": Confidence.LOW}
_TAG_RE = re.compile(r"<[^>]+>")


def _text(html: str | None) -> str:
    return _TAG_RE.sub("", html or "").strip()


class ZapImporter(Scanner):
    name: ClassVar[str] = "zap"
    binary: ClassVar[str] = ""

    def enabled(self, config: Any) -> bool:
        return False  # import-only

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        return []

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for site in raw.get("site") or []:
            for alert in site.get("alerts") or []:
                instances = alert.get("instances") or [{}]
                for inst in instances[:20]:  # ZAP can list thousands of identical instances
                    uri = inst.get("uri") or site.get("@name", "")
                    detail = " ".join(
                        p for p in (inst.get("method"), inst.get("param"), inst.get("evidence")) if p
                    )
                    cwe = str(alert.get("cweid") or "")
                    findings.append(
                        Finding(
                            tool=self.name,
                            rule_id=str(alert.get("pluginid") or alert.get("alertRef") or "zap"),
                            title=alert.get("name") or alert.get("alert") or "ZAP alert",
                            description=_text(alert.get("desc")),
                            severity=_RISK.get(str(alert.get("riskcode")), Severity.MEDIUM),
                            category=Category.DAST,
                            confidence=_CONF.get(str(alert.get("confidence")), Confidence.MEDIUM),
                            location=Location(path=uri, snippet=detail or None, in_repo=False),
                            cwe=[f"CWE-{cwe}"] if cwe.isdigit() and cwe != "0" else [],
                            remediation=_text(alert.get("solution")) or None,
                            references=[
                                ln.strip() for ln in _text(alert.get("reference")).splitlines() if ln.strip()
                            ][:5],
                        )
                    )
        return findings
