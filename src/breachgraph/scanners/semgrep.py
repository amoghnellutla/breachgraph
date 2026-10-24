"""Semgrep (SAST). Parses `semgrep scan --json` output."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from breachgraph.config import SemgrepConfig
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.scanners._util import first_sentence, read_snippet, simple_dir_excludes
from breachgraph.scanners.base import ScanContext, Scanner, Step, as_list

_CONFIDENCE = {c.value: c for c in Confidence}


class SemgrepScanner(Scanner):
    name: ClassVar[str] = "semgrep"
    binary: ClassVar[str] = "semgrep"

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        settings = cast(SemgrepConfig, self.settings(ctx.config))
        out = ctx.work_dir / "semgrep.json"
        cmd = [
            exe,
            "scan",
            "--json",
            "--output",
            str(out),
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
        ]
        for rules in settings.config:
            cmd += ["--config", rules]
        for name in simple_dir_excludes(ctx.config.exclude_paths):
            cmd += ["--exclude", name]
        cmd += [*settings.extra_args, "."]
        return [Step(cmd, out)]

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []
        for r in raw.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            path = r["path"]
            start = r.get("start", {}).get("line")
            end = r.get("end", {}).get("line")
            message = (extra.get("message") or r["check_id"]).strip()
            confidence = _CONFIDENCE.get(str(meta.get("confidence", "")).lower(), Confidence.MEDIUM)
            severity = Severity.parse(extra.get("severity"))
            # Semgrep's ERROR covers everything from "bad" to "critical"; use impact/likelihood
            # metadata (present on registry security rules) to find the critical ones.
            if (
                severity is Severity.HIGH
                and str(meta.get("impact", "")).upper() == "HIGH"
                and str(meta.get("likelihood", "")).upper() == "HIGH"
                and confidence is Confidence.HIGH
            ):
                severity = Severity.CRITICAL
            refs = [str(u) for u in as_list(meta.get("references"))]
            for key in ("source", "shortlink", "source-rule-url"):
                if isinstance(meta.get(key), str) and meta[key] not in refs:
                    refs.append(meta[key])
            fix = extra.get("fix")
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=r["check_id"],
                    title=first_sentence(message),
                    description=message,
                    severity=severity,
                    category=Category.SAST,
                    confidence=confidence,
                    location=Location(
                        path=path,
                        start_line=start,
                        end_line=end,
                        snippet=read_snippet(ctx.target, path, start, end),
                    ),
                    cwe=[str(c) for c in as_list(meta.get("cwe"))],
                    owasp=[str(o) for o in as_list(meta.get("owasp"))],
                    remediation=f"Suggested fix:\n{fix}" if fix else None,
                    references=refs,
                )
            )
        return findings
