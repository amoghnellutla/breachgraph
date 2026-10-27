"""Compare a scan with a base report (usually the default branch) to see what a change introduces.

Used as an implicit baseline: findings and attack paths already present in the base are
pre-existing, so a pull request is judged only on what it adds, without a committed baseline file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from breachgraph.config import Config
from breachgraph.models import AttackPathView, Comparison, Finding, ScanResult, Status


def load_report(path: Path) -> ScanResult:
    try:
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"{path} is not a breachgraph JSON report: {exc}") from exc


def base_fingerprints(base: ScanResult) -> set[str]:
    return {fp for f in base.findings for fp in (f.fingerprints or [f.fingerprint])}


def base_path_ids(base: ScanResult) -> set[str]:
    return {p.id for p in (base.attack_graph.paths if base.attack_graph else []) if p.id}


def compare(head: ScanResult, base: ScanResult) -> Comparison:
    head_fps = {fp for f in head.findings for fp in (f.fingerprints or [f.fingerprint])}
    head_paths = {p.id for p in (head.attack_graph.paths if head.attack_graph else []) if p.id}
    base_paths = base.attack_graph.paths if base.attack_graph else []
    return Comparison(
        base_version=base.breachgraph_version,
        base_started_at=base.started_at,
        new_paths=[p.id for p in (head.attack_graph.paths if head.attack_graph else []) if p.is_new],
        resolved_paths=[p for p in base_paths if p.id and p.id not in head_paths],
        new_findings=sum(1 for f in head.findings if f.status is Status.NEW),
        resolved_findings=sum(1 for f in base.findings if not _present(f, head_fps)),
        policy_changes=policy_changes(base.metadata.get("policy"), head.metadata.get("policy") or {}),
    )


def _present(f: Finding, fps: set[str]) -> bool:
    return any(fp in fps for fp in (f.fingerprints or [f.fingerprint]))


def path_changes(result: ScanResult) -> tuple[list[AttackPathView], list[AttackPathView]] | None:
    """(opened, closed) attack paths when the scan was compared with a base report, else None."""
    if result.comparison is None:
        return None
    new = set(result.comparison.new_paths)
    opened = [p for p in (result.attack_graph.paths if result.attack_graph else []) if p.id in new]
    return opened, result.comparison.resolved_paths


def policy_snapshot(config: Config) -> dict[str, Any]:
    """The parts of the configuration that decide what fails a build, stored in every report so
    a pull request that loosens its own gate can be called out against the base branch."""
    ag = config.attack_graph
    return {
        "fail_on": config.fail_on.model_dump(mode="json"),
        "attack_graph": {
            "enabled": ag.enabled,
            "fail_on_new_path": ag.fail_on_new_path,
            "min_confidence": ag.min_confidence,
        },
        "reachability": {"gate_on_unused": config.reachability.gate_on_unused},
        "scanners": sorted(
            n for n in type(config.scanners).model_fields if getattr(config.scanners, n).enabled
        ),
        "exclude_paths": sorted(config.exclude_paths),
        "suppressions": [_suppression(s.model_dump(mode="json")) for s in config.suppressions],
        "severity_overrides": [o.model_dump(mode="json") for o in config.severity_overrides],
    }


def _suppression(s: dict[str, Any]) -> str:
    what = s.get("fingerprint") or s.get("rule") or s.get("vuln") or "?"
    where = f" in {s['path']}" if s.get("path") else ""
    until = f", until {s['expires']}" if s.get("expires") else ", no expiry"
    return f"{what}{where} ({s.get('reason', '')}{until})"


def policy_changes(base: dict[str, Any] | None, head: dict[str, Any]) -> list[str]:
    """Plain-language differences between two policy snapshots; empty when either is missing."""
    if not base:
        return []
    out: list[str] = []
    for section in ("fail_on", "attack_graph", "reachability"):
        old, new = base.get(section) or {}, head.get(section) or {}
        for key in sorted(set(old) | set(new)):
            if old.get(key) != new.get(key):
                out.append(f"{section}.{key} changed from {_show(old.get(key))} to {_show(new.get(key))}")
    old_s, new_s = set(base.get("scanners") or []), set(head.get("scanners") or [])
    out += [f"scanner {n} turned off" for n in sorted(old_s - new_s)]
    out += [f"scanner {n} turned on" for n in sorted(new_s - old_s)]
    for key, label in (
        ("exclude_paths", "excluded path"),
        ("suppressions", "suppression"),
        ("severity_overrides", "severity override"),
    ):
        old_l = [_show(x) for x in base.get(key) or []]
        new_l = [_show(x) for x in head.get(key) or []]
        out += [f"{label} added: {x}" for x in new_l if x not in old_l]
        out += [f"{label} removed: {x}" for x in old_l if x not in new_l]
    return out


def _show(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items() if v is not None)
    return str(value)
