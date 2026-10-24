"""Risk scoring: turn severity + exploit signals + context into a 0-10 score and a P1-P4 priority.

The goal is a short, defensible "fix this first" list, not a re-statement of CVSS. Every
adjustment is recorded in ``score_reasons`` so the ranking can be explained in a report.
"""

from __future__ import annotations

from breachgraph.config import Config
from breachgraph.models import Category, Confidence, Finding, Priority, Severity
from breachgraph.paths import matches_any

BASE = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.5,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}


def _priority(score: float) -> Priority:
    if score >= 9.0:
        return Priority.P1
    if score >= 7.0:
        return Priority.P2
    if score >= 4.0:
        return Priority.P3
    return Priority.P4


def apply_overrides(findings: list[Finding], config: Config) -> None:
    for f in findings:
        for o in config.severity_overrides:
            if o.rule == f.rule_id or o.rule == f"{f.tool}:{f.rule_id}":
                f.severity = o.severity


def score(f: Finding, config: Config) -> None:
    reasons: list[str] = []
    if f.cvss is not None and f.category in (Category.SCA, Category.CONTAINER):
        base = f.cvss
        reasons.append(f"CVSS {f.cvss:.1f}")
    else:
        base = BASE[f.severity]
        reasons.append(f"{f.severity.value} severity")

    s = base
    e = f.enrichment
    if e.kev:
        s += 3.0
        reasons.append("in CISA KEV (actively exploited)")
        if e.kev_ransomware:
            reasons.append("used in ransomware campaigns")
    if e.epss is not None:
        if e.epss >= 0.1:
            bump = min(2.5, e.epss * 5)
            s += bump
            reasons.append(f"EPSS {e.epss:.1%} exploitation probability")
        elif e.epss < 0.01 and not e.kev:
            s -= 0.5
            reasons.append(f"low EPSS ({e.epss:.2%})")

    if f.confidence is Confidence.LOW:
        s -= 1.5
        reasons.append("low confidence")
    elif f.confidence is Confidence.HIGH and f.category is Category.SECRETS:
        s += 1.0
        reasons.append("high-confidence credential")

    if len(f.sources) > 1:
        s += 0.5
        reasons.append(f"confirmed by {len(f.sources)} tools")

    if f.location.in_repo and matches_any(f.location.path, config.deprioritize_paths):
        s -= 2.0
        reasons.append("test/docs path")

    if f.package and not f.package.fixed_version and f.category in (Category.SCA, Category.CONTAINER):
        reasons.append("no fix available yet")

    f.risk_score = round(max(0.0, min(10.0, s)), 1)
    f.priority = Priority.P1 if e.kev else _priority(f.risk_score)
    f.score_reasons = reasons


def score_all(findings: list[Finding], config: Config) -> None:
    apply_overrides(findings, config)
    for f in findings:
        score(f, config)
    findings.sort(
        key=lambda f: (
            -f.risk_score,
            not f.enrichment.kev,
            -(f.enrichment.epss or 0.0),
            f.location.path,
            f.location.start_line or 0,
        )
    )
