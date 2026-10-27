"""Compare a scan with a base report (usually the default branch) to see what a change introduces.

Used as an implicit baseline: findings and attack paths already present in the base are
pre-existing, so a pull request is judged only on what it adds, without a committed baseline file.
"""

from __future__ import annotations

from pathlib import Path

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
