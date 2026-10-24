"""The scan pipeline: run scanners -> normalize -> dedupe -> enrich -> score -> policy -> gate."""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from breachgraph import __version__
from breachgraph.config import Config
from breachgraph.enrich import enrich
from breachgraph.models import Finding, ScanResult, ToolRun, ToolStatus
from breachgraph.normalize import dedupe, finalize
from breachgraph.policy import (
    apply_baseline,
    apply_suppressions,
    drop_excluded,
    evaluate_gate,
    load_baseline,
)
from breachgraph.scanners import IMPORTERS, SCANNERS, ScanContext, ScannerOutcome
from breachgraph.scoring import score_all

log = logging.getLogger("breachgraph")


@dataclass
class ScanOptions:
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    imports: list[tuple[str, Path]] = field(default_factory=list)  # (tool, report path)
    baseline: Path | None = None
    offline: bool = False
    max_workers: int = 4


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
        # --only forces a scanner on even if the config disables it (except ZAP without a URL).
        if scanner.enabled(config) or (name in opts.only and name != "zap"):
            names.append(name)
    return names


def run_scanners(
    ctx: ScanContext,
    names: list[str],
    max_workers: int,
    on_done: Callable[[ToolRun], None] | None = None,
) -> list[ScannerOutcome]:
    outcomes: list[ScannerOutcome] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(SCANNERS[n].run, ctx): n for n in names}
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
    score_all(items, config)
    if opts.baseline:
        if opts.baseline.exists():
            apply_baseline(items, load_baseline(opts.baseline))
            result.baseline_used = True
        else:
            result.warnings.append(f"baseline {opts.baseline} not found; treating all findings as new")
    result.warnings += apply_suppressions(items, config)
    result.findings = items
    for run in tools:
        if run.status is ToolStatus.FAILED:
            result.warnings.append(f"{run.name} failed: {run.message}")
        elif run.status is ToolStatus.OK and run.message:
            result.warnings.append(f"{run.name}: {run.message}")
    result.gate = evaluate_gate(result, config)
    result.finished_at = datetime.now(UTC)
    return result


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

    outcomes = run_scanners(ctx, select_scanners(config, opts), opts.max_workers, on_done)
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

    findings = [f for o in outcomes for f in o.findings]
    return process(findings, [o.run for o in outcomes], config, target, opts, ctx.artifacts, started)
