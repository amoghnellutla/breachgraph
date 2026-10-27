"""Command-line interface.

Exit codes: 0 = gate passed, 1 = gate failed, 2 = usage/config error, 3 = scanner error
(only when ``fail_on.scanner_errors`` is set).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from breachgraph import __version__
from breachgraph.compare import path_changes
from breachgraph.config import CONFIG_FILENAMES, ConfigError, find_config, load_config
from breachgraph.integrations import notify
from breachgraph.integrations.github import GitHubClient, GitHubContext, write_step_summary
from breachgraph.models import Priority, ScanResult, ToolRun, ToolStatus
from breachgraph.paths import project_name
from breachgraph.pipeline import PipelineError, ScanOptions, scan
from breachgraph.policy import evaluate_gate, write_baseline
from breachgraph.reporters import FORMATS, markdown, write_reports
from breachgraph.scanners import SCANNERS

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="breachgraph: find the attack paths that matter in your code, containers and cloud.",
    rich_markup_mode="rich",
)
# CI logs are not TTYs; Rich would fall back to 80 columns and wrap every table cell.
console = Console(stderr=True, width=None if sys.stderr.isatty() else 160)
DEFAULT_BASELINE = ".breachgraph-baseline.json"
_PRIO_STYLE = {
    Priority.P1: "bold red",
    Priority.P2: "dark_orange",
    Priority.P3: "yellow",
    Priority.P4: "dim",
}


def _split(values: list[str] | None) -> list[str]:
    return [v.strip() for item in values or [] for v in item.split(",") if v.strip()]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"breachgraph {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """breachgraph: one security gate for your CI."""


@app.command("scan")
def scan_cmd(
    path: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path(),
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Config file (default: .breachgraph.yml in PATH)."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "-b",
            help=f"Accepted-findings baseline (default: {DEFAULT_BASELINE} in PATH if present).",
        ),
    ] = None,
    write_baseline_to: Annotated[
        Path | None,
        typer.Option("--write-baseline", help="Write all current findings to this baseline file and exit 0."),
    ] = None,
    compare_to: Annotated[
        Path | None,
        typer.Option(
            "--compare",
            help="A breachgraph.json from the base branch: findings and attack paths already there are "
            "treated as pre-existing, and the report says which paths this change opens or closes.",
        ),
    ] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o", help="Where reports are written.")] = Path(
        "breachgraph-report"
    ),
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            help=f"Report formats: {', '.join(FORMATS)} (repeat or comma-separate).",
        ),
    ] = None,
    only: Annotated[list[str] | None, typer.Option("--only", help="Run only these scanners.")] = None,
    skip: Annotated[list[str] | None, typer.Option("--skip", help="Skip these scanners.")] = None,
    imports: Annotated[
        list[str] | None,
        typer.Option(
            "--import",
            help="Ingest an existing report: TOOL=FILE "
            "(tools: semgrep, gitleaks, trivy, checkov, zap, sarif).",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Override the priority threshold: P1-P4 or 'none'."),
    ] = None,
    no_fail: Annotated[bool, typer.Option("--no-fail", help="Always exit 0 (report-only mode).")] = False,
    offline: Annotated[bool, typer.Option("--offline", help="Skip KEV/EPSS lookups.")] = False,
    name: Annotated[
        str | None, typer.Option("--name", help="Project name in reports (default: from the git remote).")
    ] = None,
    images: Annotated[
        list[str] | None, typer.Option("--image", help="Container image(s) to scan with Trivy.")
    ] = None,
    github_comment: Annotated[
        bool, typer.Option("--github-comment", help="Create/update a PR comment with the summary.")
    ] = False,
    github_issues: Annotated[
        str | None,
        typer.Option(
            "--github-issues", help="Open an issue per finding at this priority or above (e.g. P1)."
        ),
    ] = None,
    close_fixed: Annotated[
        bool,
        typer.Option(
            "--close-fixed-issues",
            help="Close breachgraph issues whose finding disappeared (use on the default branch).",
        ),
    ] = False,
    workers: Annotated[int, typer.Option("--workers", help="Scanners to run in parallel.")] = 4,
    keep_raw: Annotated[
        bool,
        typer.Option("--keep-raw", help="Also save each scanner's raw output in OUTPUT_DIR/raw."),
    ] = False,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help="AI-assisted triage (needs your own ANTHROPIC_API_KEY): a verdict and a concrete "
            "fix for the top findings. Advisory only; never changes the gate.",
        ),
    ] = False,
    ai_model: Annotated[
        str | None, typer.Option("--ai-model", help="Anthropic model id for --ai (e.g. a cheaper one).")
    ] = None,
    ai_budget: Annotated[
        float | None, typer.Option("--ai-budget", help="Max estimated USD to spend on --ai.")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Scan a directory and gate on the results."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING, format="%(levelname)s %(message)s"
    )
    target = path.resolve()
    try:
        config = load_config(config_file or find_config(target))
    except ConfigError as exc:
        console.print(f"[red]config error:[/] {exc}")
        raise typer.Exit(2) from exc

    if fail_on:
        config.fail_on.priority = None if fail_on.lower() == "none" else _parse_priority(fail_on)
    if images:
        config.scanners.trivy.images = [*config.scanners.trivy.images, *images]
    if ai:
        config.ai.enabled = True
    if ai_model:
        config.ai.model = ai_model
    if ai_budget is not None:
        config.ai.max_usd = ai_budget
    if config.ai.enabled:
        from breachgraph.ai import available

        ok, reason = available()
        if not ok:
            console.print(f"[yellow]--ai requested but unavailable:[/] {reason}")
            config.ai.enabled = False

    fmt_list = _split(formats) or ["json", "sarif", "html", "md"]
    bad = [f for f in fmt_list if f not in FORMATS]
    if bad:
        console.print(f"[red]unknown format(s):[/] {', '.join(bad)}")
        raise typer.Exit(2)

    parsed_imports: list[tuple[str, Path]] = []
    for item in _split(imports):
        tool, sep, file = item.partition("=")
        if not sep or not Path(file).is_file():
            console.print(f"[red]--import expects TOOL=FILE with an existing file, got[/] {item!r}")
            raise typer.Exit(2)
        parsed_imports.append((tool.strip(), Path(file)))

    if baseline is None and write_baseline_to is None and (target / DEFAULT_BASELINE).is_file():
        baseline = target / DEFAULT_BASELINE
    opts = ScanOptions(
        only=_split(only),
        skip=_split(skip),
        imports=parsed_imports,
        baseline=None if write_baseline_to else baseline,
        compare=compare_to,
        offline=offline,
        max_workers=workers,
    )

    def on_done(run: ToolRun) -> None:
        style = {"ok": "green", "imported": "cyan", "skipped": "dim", "failed": "red"}[run.status.value]
        extra = f" {run.message}" if run.message and run.status is not ToolStatus.OK else ""
        console.print(
            f"  [{style}]{run.status.value:>8}[/] {run.name:<9} {run.findings:>4} findings"
            f"  {run.duration_s:>6.1f}s{extra[:200]}"
        )

    _check_writable(output_dir)
    console.print(f"[bold]breachgraph {__version__}[/] scanning [cyan]{target}[/]")
    work_dir = Path(tempfile.mkdtemp(prefix="breachgraph-"))
    try:
        result = scan(target, config, opts, work_dir, on_done=on_done)
        result.metadata["project"] = project_name(target, name)
        _keep_artifacts(result, output_dir)
        if keep_raw:
            shutil.copytree(work_dir, output_dir / "raw", dirs_exist_ok=True)
    except PipelineError as exc:
        console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(2) from exc
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    if write_baseline_to:
        n = write_baseline(result, write_baseline_to)
        console.print(f"[green]baseline written:[/] {write_baseline_to} ({n} findings accepted)")
        raise typer.Exit(0)

    written = write_reports(result, output_dir, fmt_list)
    _print_summary(result)
    for fmt, p in written.items():
        console.print(f"  [dim]{fmt:>6}[/] {p}")

    _github(result, github_comment, github_issues, close_fixed)
    for line in notify.send(result, config.notify.on):
        console.print(f"  [dim]notify[/] {line}")

    if no_fail:
        raise typer.Exit(0)
    failed_tools = any(t.status is ToolStatus.FAILED for t in result.tools)
    if config.fail_on.scanner_errors and failed_tools:
        raise typer.Exit(3)
    raise typer.Exit(0 if result.gate.passed else 1)


def _parse_priority(value: str) -> Priority:
    try:
        return Priority(value.upper())
    except ValueError:
        console.print(f"[red]--fail-on must be P1, P2, P3, P4 or none, got[/] {value!r}")
        raise typer.Exit(2) from None


def _check_writable(output_dir: Path) -> None:
    """Fail before a long scan, not after it, when reports can't be written."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        probe = output_dir / ".breachgraph-write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        hint = ""
        if Path("/.dockerenv").exists():  # the image runs as a non-root user
            hint = ' In Docker, run as your own user: docker run --user "$(id -u):$(id -g)" ...'
        console.print(f"[red]error:[/] cannot write reports to {output_dir}: {exc.strerror or exc}.{hint}")
        raise typer.Exit(2) from exc


def _keep_artifacts(result: ScanResult, output_dir: Path) -> None:
    """Move side artifacts (SBOM) out of the temp dir before it is deleted."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, src in list(result.artifacts.items()):
        src_path = Path(src)
        if src_path.is_file():
            dest = output_dir / src_path.name
            shutil.copyfile(src_path, dest)
            result.artifacts[name] = str(dest)
        else:
            del result.artifacts[name]


def _github(result: ScanResult, comment: bool, issues: str | None, close_fixed: bool) -> None:
    gh = GitHubContext.from_env()
    md = markdown.render(result, gh.link_base if gh else None, gh.run_url if gh else None)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        write_step_summary(md)
    if not (comment or issues):
        return
    if gh is None:
        console.print("[yellow]GitHub integration needs GITHUB_TOKEN and GITHUB_REPOSITORY; skipped[/]")
        return
    client = GitHubClient(gh)
    try:
        if comment:
            console.print(f"  [dim]github[/] {client.upsert_pr_comment(md)}")
        if issues:
            summary = client.sync_issues(result, _parse_priority(issues), close_fixed)
            console.print(f"  [dim]github[/] {summary}")
    except Exception as exc:  # never let reporting mask the gate result
        console.print(f"[yellow]GitHub reporting failed (scan result unaffected):[/] {exc}")
    finally:
        client.close()


def _print_attack_paths(result: ScanResult, limit: int = 8) -> None:
    ag = result.attack_graph
    if ag is None or not ag.enabled:
        return
    if not ag.paths:
        if ag.stats.get("crown_jewels"):
            console.print("[green]No attack path[/] from the internet to a crown-jewel asset.")
        if ag.coverage:
            console.print(f"[dim]{escape(ag.coverage.line())}[/]")
        return
    console.print(f"\n[bold red]{len(ag.paths)} attack path(s) to crown-jewel assets[/]")
    if ag.coverage:
        console.print(f"[dim]{escape(ag.coverage.line())}[/]")
    for i, p in enumerate(ag.paths[:limit], 1):
        flag = " [bold red]BLOCKS[/]" if p.gating else ""
        hops = ["Internet"]
        for s in p.steps:
            hops.append(f"[bold red]{escape(s.dst)}[/]({s.via})" if s.via else escape(s.dst))
        console.print(f"  {i}. [{p.confidence}] risk {p.score}{flag}")
        console.print("     " + " → ".join(hops))
    if ag.choke_points:
        console.print("  [bold]Fix first:[/]")
        for c in ag.choke_points[:5]:
            loc = f" ({c.path}:{c.line})" if c.path else ""
            console.print(f"    - {escape(c.title)}{escape(loc)}, breaks {c.paths_cut} path(s)")


def _print_summary(result: ScanResult) -> None:
    open_findings = [f for f in result.findings if f.status.value != "suppressed"]
    table = Table(title=f"Top findings ({len(open_findings)} open)", show_lines=False, expand=False)
    for col in ("Prio", "Risk", "Finding", "Location", "Tools", "Status"):
        table.add_column(col, overflow="fold")
    for f in open_findings[:15]:
        loc = f.location.path + (f":{f.location.start_line}" if f.location.start_line else "")
        flag = " [bold red]KEV[/]" if f.enrichment.kev else ""
        if f.ai:
            flag += f" [cyan]AI: {f.ai.verdict.label}[/]"
        table.add_row(
            f"[{_PRIO_STYLE[f.priority]}]{f.priority.value}[/]",
            str(f.risk_score),
            escape(f.title[:90]) + flag,
            escape(loc[:60]),
            ",".join(f.sources),
            ("[bold red]BLOCKS[/] " if f.gating else "") + f.status.value,
        )
    if open_findings:
        console.print(table)
    changes = path_changes(result)
    if changes is not None:
        opened, closed = changes
        if opened:
            console.print(f"[bold red]This change opens {len(opened)} new attack path(s)[/]")
        if closed:
            console.print(f"[bold green]This change closes {len(closed)} attack path(s)[/]")
        if not opened and not closed:
            console.print("[dim]No change to attack paths compared with the base report.[/]")
    _print_attack_paths(result)
    ai_meta = result.metadata.get("ai")
    if isinstance(ai_meta, dict):
        bound = " (upper bound)" if ai_meta.get("cost_is_upper_bound") else ""
        console.print(
            f"[dim]AI triage: {ai_meta.get('triaged', 0)} of {ai_meta.get('attempted', 0)} finding(s), "
            f"~${ai_meta.get('cost_usd', 0):.3f}{bound} ({escape(str(ai_meta.get('model', '')))}). "
            "Verdicts and fixes are in the HTML report and PR comment.[/]"
        )
    for w in result.warnings:
        console.print(f"[yellow]warning:[/] {escape(w)}")
    if result.gate.passed:
        console.print(f"[bold green]Gate passed[/] ({result.gate.threshold})")
    else:
        console.print(f"[bold red]Gate failed:[/] {'; '.join(result.gate.reasons)} ({result.gate.threshold})")


@app.command("report")
def report_cmd(
    results: Annotated[Path, typer.Argument(help="breachgraph.json from a previous scan.")],
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o")] = Path("breachgraph-report"),
    formats: Annotated[list[str] | None, typer.Option("--format", "-f")] = None,
    config_file: Annotated[
        Path | None, typer.Option("--config", "-c", help="Re-evaluate the gate with this config.")
    ] = None,
) -> None:
    """Re-render reports (and optionally re-evaluate the gate) from a saved breachgraph.json."""
    try:
        result = ScanResult.model_validate_json(results.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        console.print(f"[red]cannot read {results}:[/] not a breachgraph.json result ({exc})")
        raise typer.Exit(2) from exc
    if config_file:
        try:
            result.gate = evaluate_gate(result, load_config(config_file))
        except ConfigError as exc:
            console.print(f"[red]config error:[/] {exc}")
            raise typer.Exit(2) from exc
    fmt_list = _split(formats) or ["html", "md", "sarif"]
    for fmt, p in write_reports(result, output_dir, fmt_list).items():
        console.print(f"{fmt:>6} {p}")


@app.command("graph")
def graph_cmd(
    path: Annotated[Path, typer.Argument(help="Directory to analyze.")] = Path(),
    config_file: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    findings_json: Annotated[
        Path | None,
        typer.Option("--findings", help="A breachgraph.json to pull code/infra findings from."),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the graph as JSON to this file.")
    ] = None,
) -> None:
    """Build the code-to-cloud attack graph only (no scanners) and print the attack paths.

    Code vulnerabilities (SSRF, injection, ...) come from a prior scan via --findings; without
    them only infrastructure-only paths (public buckets, open databases) are found.
    """
    from breachgraph.graph import build_attack_graph
    from breachgraph.graph.summary import summarize

    target = path.resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/] {target} is not a directory")
        raise typer.Exit(2)
    try:
        config = load_config(config_file or find_config(target))
    except ConfigError as exc:
        console.print(f"[red]config error:[/] {exc}")
        raise typer.Exit(2) from exc

    findings = []
    if findings_json:
        try:
            prior = ScanResult.model_validate_json(findings_json.read_text(encoding="utf-8"))
            findings = prior.findings
        except (OSError, ValidationError) as exc:
            console.print(f"[red]cannot read {findings_json}:[/] {exc}")
            raise typer.Exit(2) from exc

    ag = build_attack_graph(target, findings, config)
    summary = summarize(ag, findings, config.attack_graph, baseline_used=False)
    result = ScanResult(breachgraph_version=__version__, target=str(target), attack_graph=summary)
    _print_attack_paths(result)
    if not ag.paths:
        console.print(f"[dim]{ag.stats}[/]")
    if output:
        output.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[dim]graph written to {output}[/]")
    raise typer.Exit(1 if summary.gating_paths else 0)


@app.command("fix")
def fix_cmd(
    path: Annotated[Path, typer.Argument(help="Repository the report was made from.")] = Path(),
    report: Annotated[
        Path | None, typer.Option("--report", "-r", help="breachgraph.json (default: from the last scan).")
    ] = None,
    top: Annotated[int, typer.Option("--top", help="Fix at most this many choke points.")] = 3,
    apply: Annotated[bool, typer.Option("--apply", help="Write the fixes to the working tree.")] = False,
    pr: Annotated[
        bool, typer.Option("--pr", help="Commit each fix to its own branch and open a pull request.")
    ] = False,
) -> None:
    """Fix the findings that break the most attack paths: dependency upgrades and the GitHub Actions
    script-injection fix. Shows a diff unless --apply or --pr is given."""
    import difflib

    from breachgraph import fix as fixer

    target = path.resolve()
    report = report or target / "breachgraph-report" / "breachgraph.json"
    try:
        result = ScanResult.model_validate_json(report.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        console.print(f"[red]error:[/] cannot read {report}; run `breachgraph scan` first ({exc})")
        raise typer.Exit(2) from exc
    fixes = fixer.plan(result, target, top)
    if not fixes:
        console.print("No attack paths, so nothing to fix first.")
        raise typer.Exit(0)
    for f in fixes:
        cut = f" (breaks {f.paths_cut} path(s))" if f.paths_cut else ""
        if not f.files:
            console.print(f"[yellow]skip[/] {f.finding.title}{cut}: {f.reason}")
            continue
        console.print(f"[green]fix[/]  {f.summary}{cut}")
        for rel, new in f.files.items():
            if not (apply or pr):
                old = (target / rel).read_text(encoding="utf-8")
                diff = difflib.unified_diff(
                    old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"
                )
                console.print("".join(diff), markup=False, highlight=False)
            elif apply and not pr:
                (target / rel).write_text(new, encoding="utf-8")
        for note in f.notes:
            console.print(f"     [dim]{note}[/]")
    if pr:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        try:
            for url in fixer.open_pull_requests(fixes, result, target, token):
                console.print(f"  [dim]pull request[/] {url}")
        except fixer.FixError as exc:
            console.print(f"[red]error:[/] {exc}")
            raise typer.Exit(2) from exc
    elif not apply and any(f.files for f in fixes):
        console.print("[dim]Dry run. --apply writes these changes; --pr opens one pull request per fix.[/]")


@app.command("doctor")
def doctor_cmd() -> None:
    """Show which scanners are installed and their versions."""
    table = Table(title="breachgraph scanners")
    table.add_column("Scanner")
    table.add_column("Found")
    table.add_column("Version / path")
    missing = 0
    for name, s in SCANNERS.items():
        exe = s.executable()
        if exe:
            table.add_row(name, "[green]yes[/]", s.version() or exe)
        else:
            missing += 1
            table.add_row(name, "[red]no[/]", f"install `{s.binary}` or use the breachgraph Docker image")
    console.print(table)
    if missing:
        console.print("[dim]Missing scanners are skipped. The Docker image ships all of them pinned.[/]")


_INIT_CONFIG = """\
# breachgraph configuration. Docs: {url}/blob/main/docs/configuration.md
version: 1

scanners:
  semgrep:
    config: ["p/default"]      # any Semgrep registry ruleset or local rules dir
  gitleaks:
    scan_history: false        # true = scan every commit (finds secrets removed later)
  trivy:
    scanners: [vuln, misconfig]
    sbom: true                 # writes a CycloneDX SBOM next to the reports
  checkov: {{}}

fail_on:
  priority: P1                 # fail on new P1 findings; P2 is stricter
  kev: true                    # always fail on actively exploited CVEs
  secrets: true                # always fail on new hardcoded secrets
  new_only: true               # with a baseline, pre-existing findings don't fail the build

# Accepted risks. A reason and an expiry date are required; expired entries stop applying.
suppressions: []
#  - rule: CKV_AWS_18
#    path: infra/logging-bucket.tf
#    reason: "This is the access-log bucket itself"
#    expires: 2027-01-31
#    owner: platform-team
"""

_INIT_WORKFLOW = """\
name: breachgraph
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning
  pull-requests: write     # sticky PR comment

jobs:
  breachgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: {repo}@v0        # or pin a release commit SHA
        with:
          comment: true
"""


@app.command("init")
def init_cmd(
    path: Annotated[Path, typer.Argument(help="Repository root.")] = Path(),
    workflow: Annotated[
        bool, typer.Option("--workflow/--no-workflow", help="Also write a GitHub Actions workflow.")
    ] = True,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
) -> None:
    """Create a starter .breachgraph.yml (and GitHub workflow)."""
    from breachgraph import PROJECT_URL

    files = {path / CONFIG_FILENAMES[0]: _INIT_CONFIG.format(url=PROJECT_URL)}
    if workflow:
        repo = PROJECT_URL.removeprefix("https://github.com/")
        files[path / ".github" / "workflows" / "breachgraph.yml"] = _INIT_WORKFLOW.format(repo=repo)
    for file, content in files.items():
        if file.exists() and not force:
            console.print(f"[yellow]exists, skipped:[/] {file} (use --force)")
            continue
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        console.print(f"[green]wrote[/] {file}")
    _describe_repository(path)


def _describe_repository(path: Path) -> None:
    """What the attack graph will model in this repository, and the settings that fit it."""
    from breachgraph.graph import build_attack_graph
    from breachgraph.graph.summary import WEAKNESS_SOURCES, coverage, summarize

    try:
        config = load_config(find_config(path))
        ag = build_attack_graph(path, [], config)
    except Exception as exc:
        console.print(f"[yellow]could not inspect the repository:[/] {exc}")
        return
    summary = summarize(ag, [], config.attack_graph, baseline_used=False)
    ran = [ToolRun(name=n, status=ToolStatus.OK) for n in WEAKNESS_SOURCES]  # structure only
    cov = coverage(summary, ag, ran)
    console.print()
    console.print("[bold]What breachgraph sees here[/] (before any scanner runs)")
    console.print(
        f"  {cov.routes} HTTP routes, {cov.workloads} workloads, {cov.cloud_resources} cloud resources, "
        f"{cov.kubernetes_objects} Kubernetes objects, {cov.ci_jobs} CI jobs"
    )
    jewels = [n.name for n in ag.graph.nodes.values() if n.value >= config.attack_graph.crown_value]
    if jewels:
        more = f" and {len(jewels) - 5} more" if len(jewels) > 5 else ""
        console.print(f"  Crown jewels: {', '.join(sorted(jewels)[:5])}{more}")
    tips = [*cov.gaps]
    if any(n.attrs.get("access_key") for n in ag.graph.nodes.values()):
        tips.append(
            "Terraform manages IAM access keys: add 'credentials' to attack_graph.entry_points "
            "to see what a leaked key reaches"
        )
    if cov.kubernetes_objects:
        tips.append(
            "Kubernetes workloads found: add 'cluster' to attack_graph.entry_points to see what a "
            "compromised pod reaches"
        )
    if not jewels:
        tips.append("mark your sensitive stores as crown jewels under attack_graph.crown_jewels")
    if any("helm" in s.lower() for s in summary.skipped):
        tips.append("Helm charts are not rendered: run `helm template` into a directory and scan it")
    for tip in tips:
        console.print(f"  - {tip}")
    console.print()
    console.print("Next: [bold]breachgraph scan[/] (or commit the workflow and open a pull request).")


if __name__ == "__main__":
    app()
