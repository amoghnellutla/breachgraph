"""Checkov (IaC: Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, GitHub Actions...)."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from breachgraph.config import CheckovConfig
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.scanners._util import simple_dir_excludes
from breachgraph.scanners.base import ScanContext, Scanner, Step, as_list


class CheckovScanner(Scanner):
    name: ClassVar[str] = "checkov"
    binary: ClassVar[str] = "checkov"

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(CheckovConfig, self.settings(ctx.config))
        out = ctx.work_dir / "checkov.json"
        cmd = [exe, "-d", ".", "-o", "json", "--compact", "--quiet", "--soft-fail"]
        if settings.frameworks:
            cmd += ["--framework", *settings.frameworks]
        else:
            # sca_package needs a Prisma Cloud API key; secrets is Gitleaks' job when it is on.
            skipped = ["sca_package", "sca_image"]
            if ctx.config.scanners.gitleaks.enabled:
                skipped.append("secrets")
            cmd += ["--skip-framework", *skipped]
        for name in simple_dir_excludes(ctx.config.exclude_paths):
            cmd += ["--skip-path", name]
        cmd += settings.extra_args
        return [Step(cmd, out, stdout_to_output=True)]

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for report in as_list(raw):
            if not isinstance(report, dict):
                continue
            framework = report.get("check_type", "")
            for c in (report.get("results") or {}).get("failed_checks") or []:
                findings.append(self._finding(c, framework))
        return findings

    def _finding(self, c: dict[str, Any], framework: str) -> Finding:
        check_id = c.get("check_id", "CKV")
        line_range = c.get("file_line_range") or [None, None]
        code = c.get("code_block") or []
        snippet = "\n".join(str(line[1]).rstrip("\n") for line in code[:12]) if code else None
        is_secret = check_id.startswith("CKV_SECRET")
        resource = c.get("resource") or ""
        name = c.get("check_name") or check_id
        guideline = c.get("guideline")
        return Finding(
            tool=self.name,
            rule_id=check_id,
            title=name,
            description=(
                f"{name} (resource `{resource}`, framework {framework})."
                if resource
                else f"{name} (framework {framework})."
            ),
            # Checkov OSS does not ship severities; secrets are always serious.
            severity=Severity.parse(
                c.get("severity"), default=Severity.HIGH if is_secret else Severity.MEDIUM
            ),
            category=Category.SECRETS if is_secret else Category.IAC,
            confidence=Confidence.HIGH,
            location=Location(
                path=c.get("repo_file_path") or c.get("file_path") or "",
                start_line=line_range[0] or None,
                end_line=line_range[1] or None,
                snippet=snippet,
            ),
            cwe=["CWE-798"] if is_secret else [],
            remediation=f"See the fix guide: {guideline}" if guideline else None,
            references=[u for u in as_list(guideline) if u],
        )
