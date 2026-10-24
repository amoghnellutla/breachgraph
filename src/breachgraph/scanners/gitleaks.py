"""Gitleaks (secrets). Secrets are always redacted; breachgraph never stores the secret value."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from breachgraph.config import GitleaksConfig
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.scanners.base import ScanContext, Scanner, Step

# Credentials that grant direct access to cloud accounts, code or payments.
_CRITICAL_MARKERS = (
    "private-key",
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "stripe",
    "slack",
    "twilio",
    "sendgrid",
    "openai",
    "anthropic",
    "npm-access-token",
    "pypi",
    "heroku",
    "digitalocean",
    "shopify",
    "databricks",
    "hashicorp",
)


class GitleaksScanner(Scanner):
    name: ClassVar[str] = "gitleaks"
    binary: ClassVar[str] = "gitleaks"
    version_args: ClassVar[list[str]] = ["version"]

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(GitleaksConfig, self.settings(ctx.config))
        out = ctx.work_dir / "gitleaks.json"
        use_git = settings.scan_history and (ctx.target / ".git").exists()
        cmd = [
            exe,
            "git" if use_git else "dir",
            "--report-format",
            "json",
            "--report-path",
            str(out),
            "--redact",
            "--no-banner",
            "--exit-code",
            "0",
            "--log-level",
            "error",
            *settings.extra_args,
            ".",
        ]
        return [Step(cmd, out)]

    def accept_exit(self, code: int) -> bool:
        return code == 0

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, list):
            return []
        findings: list[Finding] = []
        for r in raw:
            rule = str(r.get("RuleID", "secret"))
            critical = any(m in rule.lower() for m in _CRITICAL_MARKERS)
            secret = r.get("Secret") or ""
            match = str(r.get("Match") or "")
            if secret and secret != "REDACTED":  # noqa: S105
                match = match.replace(secret, "REDACTED")  # belt and braces on top of --redact
            entropy = float(r.get("Entropy") or 0)
            confidence = (
                Confidence.HIGH
                if critical
                else (Confidence.LOW if 0 < entropy < 3.0 else Confidence.MEDIUM)
            )
            commit = r.get("Commit") or ""
            desc = str(r.get("Description") or rule)
            details = f"{desc} detected by rule `{rule}`."
            if commit:
                details += f" Introduced in commit {commit[:12]}"
                if r.get("Author"):
                    details += f" by {r['Author']}"
                details += ". Removing it from the latest version does not remove it from history."
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=rule,
                    title=f"Hardcoded secret: {desc}",
                    description=details,
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    category=Category.SECRETS,
                    confidence=confidence,
                    location=Location(
                        path=str(r.get("File", "")),
                        start_line=r.get("StartLine") or None,
                        end_line=r.get("EndLine") or None,
                        snippet=match[:300] or None,
                    ),
                    cwe=["CWE-798"],
                    remediation=(
                        "Revoke and rotate this credential first: assume it is compromised. "
                        "Then load it from a secret manager or environment variable, and purge it "
                        "from git history (git filter-repo / BFG) if it was ever committed."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                )
            )
        return findings
