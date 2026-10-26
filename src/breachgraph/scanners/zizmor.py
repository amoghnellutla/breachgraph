"""zizmor (GitHub Actions security: injection, dangerous triggers, unpinned actions, ...).

Online audits (known-vulnerable actions, impostor commits) run when a GitHub token is in the
environment (GH_TOKEN / GITHUB_TOKEN), as zizmor decides; without one it audits offline.
"""

from __future__ import annotations

from typing import Any, ClassVar

from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.scanners.base import ScanContext, Scanner, Step, as_list

_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "unknown": Severity.LOW,
}
_CONFIDENCE = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}
# Audits that mean code execution in the job; the rest are hardening.
_CWE = {
    "template-injection": ["CWE-94"],
    "github-env": ["CWE-94"],
    "artipacked": ["CWE-522"],
    "unpinned-uses": ["CWE-829"],
    "impostor-commit": ["CWE-829"],
    "known-vulnerable-actions": ["CWE-1395"],
    "cache-poisoning": ["CWE-349"],
    "excessive-permissions": ["CWE-250"],
    "secrets-inherit": ["CWE-250"],
    "overprovisioned-secrets": ["CWE-250"],
}


class ZizmorScanner(Scanner):
    name: ClassVar[str] = "zizmor"
    binary: ClassVar[str] = "zizmor"

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        out = ctx.work_dir / "zizmor.json"
        cmd = [exe, "--format", "json", "--no-exit-codes", "--no-progress", "--quiet"]
        cmd += [*self.settings(ctx.config).extra_args, "."]
        return [Step(cmd, out, stdout_to_output=True)]

    def accept_exit(self, code: int) -> bool:
        return code == 0  # --no-exit-codes: non-zero means zizmor itself failed

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for item in as_list(raw):
            if not isinstance(item, dict) or item.get("ignored"):
                continue
            locations = [x for x in as_list(item.get("locations")) if isinstance(x, dict)]
            primary = next(
                (x for x in locations if (x.get("symbolic") or {}).get("kind") == "Primary"),
                locations[0] if locations else None,
            )
            if primary is None:
                continue
            key = ((primary.get("symbolic") or {}).get("key") or {}).get("Local") or {}
            path = str(key.get("given_path") or key.get("verbatim_path") or "").replace("\\", "/")
            if not path:
                continue  # a remote input; breachgraph only scans the checked-out tree
            concrete = (primary.get("concrete") or {}).get("location") or {}
            start = int((concrete.get("start_point") or {}).get("row", 0)) + 1
            end = int((concrete.get("end_point") or {}).get("row", start - 1)) + 1
            ident = str(item.get("ident", "zizmor"))
            det = item.get("determinations") or {}
            note = (primary.get("symbolic") or {}).get("annotation") or ""
            desc = str(item.get("desc") or ident)
            url = item.get("url")
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=ident,
                    title=desc[:1].upper() + desc[1:] + (f": {note}" if note else ""),
                    description=f"{desc}{f' ({note})' if note else ''}. See {url}." if url else desc,
                    severity=_SEVERITY.get(str(det.get("severity", "")).lower(), Severity.LOW),
                    category=Category.CICD,
                    confidence=_CONFIDENCE.get(str(det.get("confidence", "")).lower(), Confidence.MEDIUM),
                    location=Location(
                        path=path.removeprefix("./"),
                        start_line=start,
                        end_line=max(start, end),
                        snippet=str((primary.get("concrete") or {}).get("feature") or "")[:500] or None,
                    ),
                    cwe=_CWE.get(ident, []),
                    references=[str(url)] if url else [],
                )
            )
        return findings
