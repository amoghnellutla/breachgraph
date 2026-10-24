"""OWASP ZAP (DAST) against a running application.

Runs the official ZAP container (baseline / full / api scan) through Docker. Where Docker is not
available, run ZAP in an earlier CI step and import its JSON report instead
(``secgate scan --import zap=zap.json``).
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, cast

from secgate.config import ZapConfig
from secgate.models import Category, Confidence, Finding, Location, Severity
from secgate.scanners.base import ScanContext, Scanner, Step

_SCRIPTS = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py", "api": "zap-api-scan.py"}
_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_CONF = {"4": Confidence.HIGH, "3": Confidence.HIGH, "2": Confidence.MEDIUM, "1": Confidence.LOW}
_TAG_RE = re.compile(r"<[^>]+>")


def _text(html: str | None) -> str:
    return _TAG_RE.sub("", html or "").strip()


class ZapScanner(Scanner):
    name: ClassVar[str] = "zap"
    binary: ClassVar[str] = "docker"

    def version(self) -> str | None:
        return "zap (docker)"

    def enabled(self, config: Any) -> bool:
        s = config.scanners.zap
        return bool(s.enabled and s.target_url)

    def accept_exit(self, code: int) -> bool:
        return code in (0, 1, 2)  # ZAP: 1 = FAIL alerts, 2 = WARN alerts

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(ZapConfig, self.settings(ctx.config))
        if not settings.target_url:
            return []
        target = settings.api_definition if settings.mode == "api" else settings.target_url
        args = ["-t", str(target), "-J", "zap.json", "-I"]  # -I: warnings don't change exit code
        if settings.mode == "api":
            args += ["-f", "openapi"]
        cmd = [
            exe,
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{ctx.work_dir}:/zap/wrk:rw",
            settings.docker_image,
            _SCRIPTS[settings.mode],
            *args,
            *settings.extra_args,
        ]
        return [Step(cmd, ctx.work_dir / "zap.json")]

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
                        p
                        for p in (inst.get("method"), inst.get("param"), inst.get("evidence"))
                        if p
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
                                ln.strip()
                                for ln in _text(alert.get("reference")).splitlines()
                                if ln.strip()
                            ][:5],
                        )
                    )
        return findings
