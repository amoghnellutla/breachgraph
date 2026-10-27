"""Run breachgraph on every benchmark target and store a compact, reviewable result per target.

    python benchmarks/run.py                       # all targets, image breachgraph:dev
    python benchmarks/run.py --only terragoat      # one target
    python benchmarks/run.py --image ghcr.io/amoghnellutla/breachgraph:v0.1.0

Needs git and Docker. Targets are cloned at their pinned commit into .tmp/bench/ (disposable).
Results go to benchmarks/results/<name>.json; label the paths in benchmarks/labels/<name>.yml
and build docs/benchmark.md with benchmarks/report.py.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".tmp" / "bench"
RESULTS = ROOT / "benchmarks" / "results"


def path_key(path: dict[str, Any]) -> str:
    """Human-readable identity of an attack path, used to match labels to results."""
    return " -> ".join(["Internet", *(s["dst"] for s in path["steps"])])


def checkout(target: dict[str, Any]) -> Path:
    dest = WORK / target["name"]
    if (dest / ".git").is_dir():
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True)
        if head.stdout.strip() == target["sha"]:
            return dest
    dest.mkdir(parents=True, exist_ok=True)
    git = ["git", "-C", str(dest)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "remote", "remove", "origin"], capture_output=True)
    subprocess.run([*git, "remote", "add", "origin", target["repo"]], check=True)
    subprocess.run([*git, "fetch", "-q", "--depth", "1", "origin", target["sha"]], check=True)
    subprocess.run(
        [*git, "-c", "advice.detachedHead=false", "checkout", "-q", "--force", "FETCH_HEAD"], check=True
    )
    return dest


def scan(target: dict[str, Any], src: Path, image: str) -> tuple[dict[str, Any], float]:
    out = src / ".breachgraph-bench"
    started = time.monotonic()
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{src}:/src",
            image,
            "scan",
            ".",
            "-o",
            ".breachgraph-bench",
            "-f",
            "json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    elapsed = time.monotonic() - started
    report = out / "breachgraph.json"
    if proc.returncode not in (0, 1) or not report.is_file():
        raise RuntimeError(f"{target['name']}: scan failed (exit {proc.returncode}): {proc.stderr[-2000:]}")
    return json.loads(report.read_text(encoding="utf-8")), elapsed


def summarize(target: dict[str, Any], report: dict[str, Any], elapsed: float) -> dict[str, Any]:
    findings = report["findings"]
    open_findings = [f for f in findings if f["status"] != "suppressed"]
    ag = report.get("attack_graph") or {}
    priorities: dict[str, int] = {}
    for f in open_findings:
        priorities[f["priority"]] = priorities.get(f["priority"], 0) + 1
    return {
        "name": target["name"],
        "repo": target["repo"],
        "sha": target["sha"],
        "kind": target["kind"],
        "breachgraph_version": report["breachgraph_version"],
        "wall_time_s": round(elapsed, 1),
        "tools": [
            {k: t.get(k) for k in ("name", "status", "version", "findings", "duration_s", "message")}
            for t in report["tools"]
        ],
        "raw_findings": sum(t.get("findings") or 0 for t in report["tools"]),
        "findings": len(open_findings),
        "multi_tool_findings": sum(1 for f in open_findings if len(f.get("sources") or []) > 1),
        "by_priority": dict(sorted(priorities.items())),
        "gating_findings": sum(1 for f in open_findings if f.get("gating")),
        "graph_stats": ag.get("stats", {}),
        "blind_spots": ag.get("skipped", []),
        "attack_paths": [
            {
                "key": path_key(p),
                "target": p["target"],
                "confidence": p["confidence"],
                "gating": p["gating"],
                "score": p["score"],
                "weapons": [s["weakness_title"] for s in p["steps"] if s.get("via")],
                "evidence": [
                    f"{s['evidence_path']}:{s['evidence_line']}" for s in p["steps"] if s.get("evidence_path")
                ],
            }
            for p in ag.get("paths", [])
        ],
        "choke_points": [
            {"title": c["title"], "paths_cut": c["paths_cut"], "at": f"{c.get('path')}:{c.get('line')}"}
            for c in ag.get("choke_points", [])
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default="breachgraph:dev")
    ap.add_argument("--only", action="append", default=[], help="target name (repeatable)")
    opts = ap.parse_args()
    targets = yaml.safe_load((ROOT / "benchmarks" / "targets.yml").read_text(encoding="utf-8"))
    RESULTS.mkdir(parents=True, exist_ok=True)
    failed = 0
    for target in targets:
        if opts.only and target["name"] not in opts.only:
            continue
        try:
            src = checkout(target)
            report, elapsed = scan(target, src, opts.image)
        except (subprocess.CalledProcessError, RuntimeError) as exc:
            print(f"FAIL  {target['name']}: {exc}")
            failed += 1
            continue
        result = summarize(target, report, elapsed)
        (RESULTS / f"{target['name']}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"ok    {target['name']:<16} {result['raw_findings']:>5} raw -> {result['findings']:>5} findings, "
            f"{len(result['attack_paths'])} paths, {result['wall_time_s']}s"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
