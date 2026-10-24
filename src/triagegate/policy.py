"""Path exclusion, baselines, suppressions and the pass/fail gate."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from triagegate.config import Config, Suppression
from triagegate.models import Category, Finding, GateResult, ScanResult, Status, ToolStatus
from triagegate.paths import glob_match, matches_any

BASELINE_VERSION = 1


def drop_excluded(findings: list[Finding], config: Config) -> list[Finding]:
    return [
        f
        for f in findings
        if not f.location.in_repo or not matches_any(f.location.path, config.exclude_paths)
    ]


# ---------------------------------------------------------------- baseline


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"{path} is not a triagegate baseline file")
    fps: set[str] = set()
    for item in data["findings"]:
        fps.update(item.get("fingerprints") or [item["fingerprint"]])
    return fps


def write_baseline(result: ScanResult, path: Path) -> int:
    keep = [f for f in result.findings if f.status is not Status.SUPPRESSED]
    payload: dict[str, Any] = {
        "version": BASELINE_VERSION,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "triagegate_version": result.triagegate_version,
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "fingerprints": f.fingerprints,
                "tool": f.tool,
                "rule_id": f.rule_id,
                "path": f.location.path,
                "title": f.title,
                "severity": f.severity.value,
            }
            for f in sorted(keep, key=lambda f: (f.location.path, f.rule_id, f.fingerprint))
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(keep)


def apply_baseline(findings: list[Finding], baseline: set[str]) -> None:
    for f in findings:
        if any(fp in baseline for fp in f.fingerprints):
            f.status = Status.BASELINE


# ---------------------------------------------------------------- suppressions


def _matches(s: Suppression, f: Finding) -> bool:
    if s.fingerprint and s.fingerprint not in f.fingerprints:
        return False
    if (
        s.rule
        and s.rule not in (f.rule_id, f"{f.tool}:{f.rule_id}")
        and s.rule not in f.related_rules
    ):
        return False
    if s.vuln and s.vuln.upper() not in (v.upper() for v in f.vuln_ids):
        return False
    return not (s.path and not glob_match(f.location.path, s.path))


def apply_suppressions(
    findings: list[Finding], config: Config, today: date | None = None
) -> list[str]:
    today = today or date.today()
    warnings: list[str] = []
    expired_reported: set[int] = set()
    for f in findings:
        for i, s in enumerate(config.suppressions):
            if not _matches(s, f):
                continue
            if s.expires and s.expires < today:
                if i not in expired_reported:
                    expired_reported.add(i)
                    label = s.fingerprint or s.rule or s.vuln
                    warnings.append(
                        f"suppression for {label} expired on {s.expires.isoformat()}; "
                        "its findings count again. Fix them or renew the suppression."
                    )
                continue
            f.status = Status.SUPPRESSED
            f.suppression_reason = s.reason + (f" (owner: {s.owner})" if s.owner else "")
            break
    return warnings


# ---------------------------------------------------------------- gate


def evaluate_gate(result: ScanResult, config: Config) -> GateResult:
    rules = config.fail_on
    statuses = (Status.NEW,) if rules.new_only else (Status.NEW, Status.BASELINE)
    reasons: list[str] = []
    gating = 0
    for f in result.findings:
        f.gating = False
        if f.status not in statuses:
            continue
        why = None
        if rules.kev and f.enrichment.kev:
            why = "known exploited (KEV)"
        elif rules.secrets and f.category is Category.SECRETS:
            why = "secret"
        elif rules.priority and f.priority.rank >= rules.priority.rank:
            why = f"priority {f.priority.value}"
        elif rules.severity and f.severity.rank >= rules.severity.rank:
            why = f"severity {f.severity.value}"
        if why:
            f.gating = True
            gating += 1

    threshold = []
    if rules.priority:
        threshold.append(f"priority >= {rules.priority.value}")
    if rules.severity:
        threshold.append(f"severity >= {rules.severity.value}")
    if rules.kev:
        threshold.append("any KEV")
    if rules.secrets:
        threshold.append("any secret")
    scope = "new " if rules.new_only and result.baseline_used else ""

    if gating:
        reasons.append(f"{gating} {scope}finding(s) at or above the threshold")
    failed_tools = [t.name for t in result.tools if t.status is ToolStatus.FAILED]
    if failed_tools and rules.scanner_errors:
        reasons.append("scanner(s) failed: " + ", ".join(failed_tools))
    return GateResult(passed=not reasons, reasons=reasons, threshold=", ".join(threshold))
