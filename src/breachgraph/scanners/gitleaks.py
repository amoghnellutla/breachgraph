"""Gitleaks (secrets). Secrets are always redacted; breachgraph never stores the secret value.

A secret finding gates a merge unconditionally, so it has to be nearly always right. On 32 real
projects, 95% of what Gitleaks reported was its generic-api-key rule, and every project would have
failed. So only a key in a provider's own format, in code that runs, blocks. The rest is reported
at low confidence, and checksums in lock files aren't findings at all.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar, cast

from breachgraph.config import GitleaksConfig
from breachgraph.graph.model import not_run
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


# Rules that match a shape, not a provider's format: a guess, however high the entropy.
_GUESSES = {
    "generic-api-key",
    "curl-auth-header",
    "curl-auth-user",
    "jwt",
    "jwt-base64",
    "kubernetes-secret-yaml",
}
_LOCK_FILE = re.compile(
    r"(?:^|/)(?:[^/]*\.lock|[^/]*-lock\.(?:json|ya?ml)|go\.sum|npm-shrinkwrap\.json|uv\.lock|Gemfile\.lock)$",
    re.I,
)
_HASH = re.compile(r"(?<![0-9a-zA-Z])(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-zA-Z])")
_NAMED_SECRET = re.compile(r"key|token|secret|passw|credential|auth", re.I)
_NOT_REAL_FILE = re.compile(
    r"\.(?:example|sample|template|dist|tmpl)(?:\.|$)|\.mdx?$|\.rst$"
    r"|(?:^|[/._-])(?:test\w*|mock\w*|fake\w*|fixtures?|benchmarks?|localhost\w*|devcontainer|stacktraces)"
    r"(?:[/._-]|$)",
    re.I,
)
_HASH_FILE = re.compile(
    r"(?:^|[-_./])(?:hash(?:es)?|checksums?|sha\d*sums?|integrity)[^/]*\.(?:json|txt|ya?ml|sum|csv)$", re.I
)
_NOT_REAL_VALUE = re.compile(
    r"sk_test_|pk_test_|rk_test_|EXAMPLE|example\.com|changeme|change[-_]me|placeholder|dummy"
    r"|\bfake|x{8,}|your[-_ ]",
    re.I,
)


def _line(target: Path, rel: str, number: int) -> str:
    """The flagged line, read only to judge it; it is never stored."""
    try:
        with (target / rel).open(encoding="utf-8", errors="replace") as handle:
            for i, text in enumerate(handle, 1):
                if i == number:
                    return text
    except OSError:
        pass
    return ""


def verdict(rule: str, rel: str, line: str) -> str:
    """ "drop" (not a secret), "report" (a person may want to look) or "block"."""
    if _LOCK_FILE.search(rel) or _HASH_FILE.search(rel):
        return "drop"
    guess = rule in _GUESSES or rule.startswith("generic")
    if guess and _HASH.search(line) and not _NAMED_SECRET.search(line):
        return "drop"  # a checksum: many real API keys are hex too, so the line has to not say so
    if guess or not_run(rel) or _NOT_REAL_FILE.search(rel) or _NOT_REAL_VALUE.search(line):
        return "report"
    return "block"


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
            rel = str(r.get("File", ""))
            decision = verdict(rule, rel, _line(ctx.target, rel, int(r.get("StartLine") or 0)))
            if decision == "drop":
                continue
            critical = any(m in rule.lower() for m in _CRITICAL_MARKERS)
            secret = r.get("Secret") or ""
            match = str(r.get("Match") or "")
            if secret and secret != "REDACTED":  # noqa: S105
                match = match.replace(secret, "REDACTED")  # belt and braces on top of --redact
            confidence = Confidence.LOW if decision == "report" else Confidence.HIGH
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
                    severity=(
                        Severity.LOW
                        if decision == "report"
                        else Severity.CRITICAL
                        if critical
                        else Severity.HIGH
                    ),
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
