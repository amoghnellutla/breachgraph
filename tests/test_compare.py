"""Stable attack-path ids, comparison with a base report, and the "this change opens a path" headline."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.models import AttackGraphSummary, AttackPathView, AttackStep, Comparison, ScanResult
from breachgraph.pipeline import ScanOptions, process
from breachgraph.policy import load_baseline_paths, write_baseline
from breachgraph.reporters import markdown
from tests.test_pipeline_attackgraph import CMDI, PLATFORM, SSRF, TOOLS


def run(findings, tmp: Path | None = None, base: ScanResult | None = None, **opts):  # type: ignore[no-untyped-def]
    compare = None
    if base is not None and tmp is not None:
        compare = tmp / "base.json"
        compare.write_text(base.model_dump_json(), encoding="utf-8")
    return process(
        [f.model_copy(deep=True) for f in findings],
        TOOLS,
        Config(),
        PLATFORM,
        ScanOptions(offline=True, compare=compare, **opts),
    )


def ids(result: ScanResult) -> set[str]:
    return {p.id for p in result.attack_graph.paths} if result.attack_graph else set()


def test_path_ids_are_stable() -> None:
    a, b = run([SSRF, CMDI]), run([CMDI, SSRF])
    assert ids(a) == ids(b) and len(ids(a)) == 2 and all(len(i) == 16 for i in ids(a))
    path = a.attack_graph.paths[0]  # type: ignore[union-attr]
    assert path.node_ids[0] == "internet" and len(path.node_ids) == len(path.steps) + 1


def test_change_that_fixes_a_vector_closes_its_path(tmp_path: Path) -> None:
    base = run([SSRF, CMDI])
    head = run([CMDI], tmp_path, base)
    assert head.comparison is not None
    assert len(head.comparison.resolved_paths) == 1 and head.comparison.new_paths == []
    assert head.comparison.resolved_findings == 1
    assert head.gate.passed  # the remaining path already existed on the base branch
    md = markdown.render(head)
    assert "This change closes 1 attack path(s)" in md and "~~Internet →" in md


def test_change_that_adds_a_vector_opens_a_path(tmp_path: Path) -> None:
    base = run([CMDI])
    head = run([SSRF, CMDI], tmp_path, base)
    assert head.comparison is not None and len(head.comparison.new_paths) == 1
    gating = head.attack_graph.gating_paths  # type: ignore[union-attr]
    assert [p.id for p in gating] == head.comparison.new_paths  # only the new path blocks
    md = markdown.render(head)
    assert "This change opens 1 new attack path(s)" in md and "```mermaid" in md


def test_unchanged_paths(tmp_path: Path) -> None:
    base = run([SSRF, CMDI])
    head = run([SSRF, CMDI], tmp_path, base)
    assert "No change to attack paths" in markdown.render(head)
    assert not head.attack_graph.gating_paths  # type: ignore[union-attr]


def test_bad_compare_file_is_a_warning(tmp_path: Path) -> None:
    bad = tmp_path / "base.json"
    bad.write_text("{}", encoding="utf-8")
    res = process([], TOOLS, Config(), PLATFORM, ScanOptions(offline=True, compare=bad))
    assert res.comparison is None and any("comparison skipped" in w for w in res.warnings)


def test_baseline_records_paths(tmp_path: Path) -> None:
    base = run([SSRF, CMDI])
    path = tmp_path / "baseline.json"
    write_baseline(base, path)
    assert load_baseline_paths(path) == ids(base)
    head = run([SSRF, CMDI], baseline=path)
    assert not head.attack_graph.gating_paths  # type: ignore[union-attr]


def test_mermaid_labels_cannot_break_out() -> None:
    hostile = 'evil"] --> x["pwn <img src=x> `code` @team %%{init: {"theme":"dark"}}%% #quot;'
    path = AttackPathView(
        id="x",
        target=hostile,
        target_kind="datastore",
        score=1,
        confidence="high",
        length=1,
        steps=[AttackStep(src="Internet", dst=hostile, dst_kind="datastore", kind="exposes", via="ssrf")],
    )
    result = ScanResult(breachgraph_version="t", target="/x", comparison=Comparison(new_paths=["x"]))
    result.attack_graph = AttackGraphSummary(paths=[path])
    block = markdown.render(result).split("```mermaid")[1].split("```")[0]
    labels = [line for line in block.splitlines() if "[" in line]
    for line in labels:
        inner = line.split('["', 1)[1].rsplit('"]', 1)[0]
        assert not any(c in inner for c in '"<>`@%#{}[];')


def test_html_shows_the_change(tmp_path: Path) -> None:
    from breachgraph.reporters import html

    head = run([SSRF, CMDI], tmp_path, run([CMDI]))
    page = html.render(head)
    assert "This change opens 1 new attack path(s)" in page
