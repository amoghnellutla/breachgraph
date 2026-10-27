"""The scan pipeline: run scanners -> normalize -> dedupe -> enrich -> score -> policy -> gate."""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from breachgraph import __version__, incremental
from breachgraph.compare import base_fingerprints, base_path_ids, compare, load_report, policy_snapshot
from breachgraph.config import Config
from breachgraph.enrich import enrich
from breachgraph.graph import build_attack_graph
from breachgraph.graph.summary import coverage, summarize
from breachgraph.models import Finding, ScanResult, ToolRun, ToolStatus
from breachgraph.normalize import dedupe, finalize
from breachgraph.policy import (
    apply_baseline,
    apply_suppressions,
    drop_excluded,
    evaluate_gate,
    load_baseline,
    load_baseline_paths,
)
from breachgraph.reachability import annotate_reachability
from breachgraph.scanners import IMPORTERS, SCANNERS, ScanContext, ScannerOutcome
from breachgraph.scoring import score_all

log = logging.getLogger("breachgraph")


@dataclass
class ScanOptions:
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    imports: list[tuple[str, Path]] = field(default_factory=list)  # (tool, report path)
    baseline: Path | None = None
    compare: Path | None = None  # base report: an implicit baseline of findings and attack paths
    offline: bool = False
    max_workers: int = 4
    incremental: bool = False  # with compare: rescan only what changed since the base report


class PipelineError(Exception):
    pass


def select_scanners(config: Config, opts: ScanOptions) -> list[str]:
    unknown = [n for n in [*opts.only, *opts.skip] if n not in SCANNERS]
    if unknown:
        raise PipelineError(f"unknown scanner(s): {', '.join(unknown)}; known: {', '.join(SCANNERS)}")
    imported = {tool for tool, _ in opts.imports}
    names = []
    for name, scanner in SCANNERS.items():
        if name in imported or name in opts.skip:
            continue
        if opts.only and name not in opts.only:
            continue
        # --only forces a scanner on even if the config disables it.
        if scanner.enabled(config) or name in opts.only:
            names.append(name)
    return names


def run_scanners(
    ctx: ScanContext,
    names: list[str],
    max_workers: int,
    on_done: Callable[[ToolRun], None] | None = None,
    contexts: dict[str, ScanContext] | None = None,
) -> list[ScannerOutcome]:
    outcomes: list[ScannerOutcome] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(SCANNERS[n].run, (contexts or {}).get(n, ctx)): n for n in names}
        for fut in as_completed(futures):
            try:
                outcome = fut.result()
            except Exception as exc:  # adapter bug: keep the other scanners' results
                log.exception("scanner %s crashed", futures[fut])
                outcome = ScannerOutcome(
                    ToolRun(
                        name=futures[fut],
                        status=ToolStatus.FAILED,
                        message=f"internal error: {exc}",
                    )
                )
            outcomes.append(outcome)
            if on_done:
                on_done(outcome.run)
    outcomes.sort(key=lambda o: names.index(o.run.name))
    return outcomes


def process(
    findings: list[Finding],
    tools: list[ToolRun],
    config: Config,
    target: Path,
    opts: ScanOptions,
    artifacts: dict[str, str] | None = None,
    started_at: datetime | None = None,
) -> ScanResult:
    result = ScanResult(
        breachgraph_version=__version__,
        target=str(target),
        tools=tools,
        artifacts=artifacts or {},
    )
    if started_at:
        result.started_at = started_at
    items = drop_excluded(finalize(findings), config)
    items = dedupe(items)
    result.warnings += enrich(items, config.enrich, offline=opts.offline)
    if config.reachability.enabled:
        try:
            annotate_reachability(target, items, config, offline=opts.offline)
        except Exception as exc:  # reachability is best-effort; never break a scan
            log.exception("reachability analysis failed")
            result.warnings.append(f"reachability analysis skipped: {exc}")
    score_all(items, config)
    baseline_paths: set[str] | None = None
    if opts.baseline:
        if opts.baseline.exists():
            apply_baseline(items, load_baseline(opts.baseline))
            baseline_paths = load_baseline_paths(opts.baseline)
            result.baseline_used = True
        else:
            result.warnings.append(f"baseline {opts.baseline} not found; treating all findings as new")
    base: ScanResult | None = None
    if opts.compare:
        try:
            base = load_report(opts.compare)
        except (OSError, ValueError) as exc:
            result.warnings.append(f"comparison skipped: {exc}")
        else:
            apply_baseline(items, base_fingerprints(base))
            baseline_paths = (baseline_paths or set()) | base_path_ids(base)
            result.baseline_used = True
    result.warnings += apply_suppressions(items, config)
    result.findings = items
    if config.attack_graph.enabled:
        try:
            ag = build_attack_graph(target, items, config)
            result.attack_graph = summarize(
                ag, items, config.attack_graph, result.baseline_used, baseline_paths
            )
            result.attack_graph.coverage = coverage(result.attack_graph, ag, tools)
        except Exception as exc:  # the attack graph must never break a scan
            log.exception("attack graph failed")
            result.warnings.append(f"attack graph skipped: {exc}")
    for run in tools:
        if run.status is ToolStatus.FAILED:
            result.warnings.append(f"{run.name} failed: {run.message}")
        elif run.status is ToolStatus.OK and run.message:
            result.warnings.append(f"{run.name}: {run.message}")
    result.metadata["policy"] = policy_snapshot(config)
    if base is not None:
        result.comparison = compare(result, base)
    result.gate = evaluate_gate(result, config)
    result.metadata["vex"] = config.vex.model_dump()
    if config.ai.enabled:
        _run_ai(result, config, target)
    result.finished_at = datetime.now(UTC)
    return result


def _run_ai(result: ScanResult, config: Config, target: Path) -> None:
    from breachgraph.ai import AIUnavailable, triage

    try:
        run = triage(result, config.ai, target)
    except AIUnavailable as exc:
        result.warnings.append(f"AI triage unavailable: {exc}")
        return
    except Exception as exc:  # AI must never break a scan
        log.exception("AI triage failed")
        result.warnings.append(f"AI triage failed: {exc}")
        return
    result.warnings.extend(run.warnings)
    result.metadata["ai"] = {
        "model": run.model,
        "attempted": run.attempted,
        "triaged": run.triaged,
        "cost_usd": round(run.cost_usd, 4),
        "cost_is_upper_bound": run.cost_is_upper_bound,
        "input_tokens": run.input_tokens,
        "output_tokens": run.output_tokens,
    }


def scan(
    target: Path,
    config: Config,
    opts: ScanOptions,
    work_dir: Path,
    on_done: Callable[[ToolRun], None] | None = None,
) -> ScanResult:
    started = datetime.now(UTC)
    target = target.resolve()
    if not target.is_dir():
        raise PipelineError(f"{target} is not a directory")
    work_dir.mkdir(parents=True, exist_ok=True)
    work_dir.chmod(0o777)  # the ZAP container runs as a non-root user and writes here
    ctx = ScanContext(target=target, work_dir=work_dir, config=config)

    names = select_scanners(config, opts)
    tree = incremental.tree_digest(target, config.exclude_paths)
    base = _base_for_incremental(opts)
    plan = incremental.plan(base, tree, config, __version__, names) if opts.incremental else None
    run = [n for n in names if plan is None or plan.modes[n] != "carry"]
    contexts = {
        n: ScanContext(target=target, work_dir=work_dir, config=config, artifacts=ctx.artifacts, files=fs)
        for n, fs in (plan.files if plan else {}).items()
    }
    outcomes = run_scanners(ctx, run, opts.max_workers, on_done, contexts)
    reused = (
        incremental.carried(base, plan) if plan is not None and base is not None and not plan.reason else []
    )
    for n in names:
        if n in run:
            continue
        count = sum(1 for f in reused if f.tool == n)
        tool_run = ToolRun(
            name=n,
            status=ToolStatus.OK,
            findings=count,
            message=f"no relevant change: {count} finding(s) reused",
        )
        outcomes.append(ScannerOutcome(tool_run, []))
        if on_done:
            on_done(tool_run)
    for tool, path in opts.imports:
        if tool not in IMPORTERS:
            raise PipelineError(f"cannot import '{tool}': supported are {', '.join(IMPORTERS)}")
        try:
            outcome = IMPORTERS[tool].import_file(path, ctx)
        except (OSError, ValueError) as exc:
            outcome = ScannerOutcome(ToolRun(name=tool, status=ToolStatus.FAILED, message=str(exc)))
        outcomes.append(outcome)
        if on_done:
            on_done(outcome.run)

    findings = [f for o in outcomes for f in o.findings] + reused
    result = process(findings, [o.run for o in outcomes], config, target, opts, ctx.artifacts, started)
    result.metadata["tree"] = tree
    result.metadata["scanner_fingerprint"] = incremental.scanner_fingerprint(config)
    if plan is not None:
        result.metadata["incremental"] = {
            "full_scan_reason": plan.reason,
            "changed_files": len(plan.changed),
            "deleted_files": len(plan.deleted),
            "modes": plan.modes,
        }
    return result


def _base_for_incremental(opts: ScanOptions) -> ScanResult | None:
    if not (opts.incremental and opts.compare and opts.compare.is_file()):
        return None
    try:
        return load_report(opts.compare)
    except ValueError:
        return None  # process() reports the unreadable base as a warning
