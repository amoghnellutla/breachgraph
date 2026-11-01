"""Does this change open an attack path? The question to ask before a pull request exists.

The first check scans the repository and keeps the report in the cache directory as the base.
After that, only what changed is rescanned and compared with it, so an editor, a pre-commit hook or
an AI coding assistant can ask after every change. The working tree is never written to.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Any

from breachgraph.compare import path_changes
from breachgraph.config import Config
from breachgraph.enrich import cache_dir
from breachgraph.models import AttackPathView, ScanResult
from breachgraph.pipeline import ScanOptions, scan


def base_path(target: Path) -> Path:
    digest = hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]
    return cache_dir() / "check" / f"{digest}.json"


def _route(path: AttackPathView) -> str:
    return " -> ".join(["Internet", *(s.dst for s in path.steps)])


def _path(path: AttackPathView) -> dict[str, Any]:
    weapons = [
        {"needs": s.via, "finding": s.weakness_title, "at": f"{s.evidence_path}:{s.evidence_line}"}
        for s in path.steps
        if s.via
    ]
    return {"target": path.target, "route": _route(path), "confidence": path.confidence, "weapons": weapons}


def run_check(target: Path, config: Config, update_base: bool = False) -> dict[str, Any]:
    """{"status": "baseline" | "clear" | "opens", ...}: what this working tree changes."""
    target = target.resolve()
    base = base_path(target)
    work = Path(tempfile.mkdtemp(prefix="breachgraph-check-"))
    try:
        if update_base or not base.is_file():
            result = scan(target, config, ScanOptions(offline=True, incremental=True), work)
            _save(result, base)
            return {
                "status": "baseline",
                "message": "Saved this tree as the base. The next check compares with it.",
                "attack_paths": len(result.attack_graph.paths) if result.attack_graph else 0,
            }
        result = scan(target, config, ScanOptions(offline=True, compare=base, incremental=True), work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return summary(result)


def _save(result: ScanResult, base: Path) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(result.model_dump_json(), encoding="utf-8")


def summary(result: ScanResult) -> dict[str, Any]:
    opened, closed = path_changes(result) or ([], [])
    ag = result.attack_graph
    wider = set(result.comparison.wider_exposures) if result.comparison else set()
    exposures = [x for x in (ag.exposures or []) if x.id in wider] if ag else []
    return {
        "status": "opens" if opened else "clear",
        "opens": [_path(p) for p in opened],
        "closes": [_route(p) for p in closed],
        "one_bug_away": [{"entry": x.entry, "target": x.target, "harden": x.harden} for x in exposures],
        "new_findings": result.comparison.new_findings if result.comparison else 0,
        "incomplete": result.gate.incomplete,
    }
