"""Incremental pull-request scans: rescan what changed, reuse the rest, fall back when unsure."""

from pathlib import Path
from typing import Any, ClassVar

import pytest

from breachgraph import __version__, incremental, pipeline
from breachgraph.config import Config
from breachgraph.models import (
    Category,
    Confidence,
    Finding,
    Location,
    ScanResult,
    Severity,
    ToolRun,
    ToolStatus,
)
from breachgraph.normalize import fingerprint_of
from breachgraph.pipeline import ScanOptions, scan
from breachgraph.reporters import markdown
from breachgraph.scanners.base import ScanContext, ScannerOutcome
from tests.test_entry_points import write

NAMES = ["semgrep", "checkov", "trivy", "gitleaks", "zizmor", "cicd"]


def base_with(tree: dict[str, str], config: Config, **meta: Any) -> ScanResult:
    r = ScanResult(breachgraph_version=__version__, target=".")
    r.metadata.update({"tree": tree, "scanner_fingerprint": incremental.scanner_fingerprint(config), **meta})
    return r


def test_plan_picks_the_least_work_that_is_still_correct() -> None:
    cfg = Config()
    base = base_with({"app.py": "a", "main.tf": "b", "requirements.txt": "c", "x.py": "d"}, cfg)
    p = incremental.plan(
        base, {"app.py": "A", "main.tf": "b", "requirements.txt": "c", "new.py": "n"}, cfg, __version__, NAMES
    )
    assert p.changed == {"app.py", "new.py"} and p.deleted == {"x.py"} and not p.reason
    assert p.modes == {
        "semgrep": "files", "checkov": "carry", "trivy": "carry",
        "gitleaks": "full", "zizmor": "carry", "cicd": "full",
    }  # fmt: skip
    assert p.files["semgrep"] == ["app.py", "new.py"]
    p2 = incremental.plan(
        base, {**base.metadata["tree"], "main.tf": "B", "requirements.txt": "C"}, cfg, __version__, NAMES
    )
    assert (
        p2.modes["checkov"] == "files" and p2.files["checkov"] == ["main.tf"] and p2.modes["trivy"] == "full"
    )


@pytest.mark.parametrize(
    ("base", "reason"),
    [
        (None, "no base report"),
        (ScanResult(breachgraph_version=__version__, target="."), "no file digests"),
        (ScanResult(breachgraph_version="0.0.1", target=".", metadata={"tree": {}}), "breachgraph 0.0.1"),
        (
            ScanResult(
                breachgraph_version=__version__, target=".", metadata={"tree": {}, "scanner_fingerprint": "x"}
            ),
            "settings differ",
        ),
    ],
)
def test_full_scan_when_the_base_cannot_be_trusted(base: ScanResult | None, reason: str) -> None:
    p = incremental.plan(base, {}, Config(), __version__, NAMES)
    assert reason in p.reason and set(p.modes.values()) == {"full"}


def f(tool: str, path: str, rule: str = "r") -> Finding:
    return Finding(
        tool=tool, rule_id=rule, title=rule, severity=Severity.HIGH, category=Category.SAST,
        confidence=Confidence.HIGH, location=Location(path=path, start_line=1, snippet=f"{path} {rule}"),
        fingerprint=f"{tool}:{path}:{rule}", sources=[tool, "other"],
    )  # fmt: skip


def test_carried_findings_keep_their_identity_and_appear_once() -> None:
    base = ScanResult(breachgraph_version=__version__, target=".")
    base.findings = [
        f("semgrep", "app.py"),
        f("semgrep", "lib.py"),
        f("trivy", "requirements.txt"),
        f("gitleaks", "a.env"),
    ]
    p = incremental.Plan(changed={"app.py"}, modes={"semgrep": "files", "trivy": "carry", "gitleaks": "full"})
    out = incremental.carried(base, p)
    assert [(c.tool, c.location.path) for c in out] == [("semgrep", "lib.py"), ("trivy", "requirements.txt")]
    assert out[0].sources == ["semgrep", "other"]  # untouched; finalize recomputes it


class Recorder:
    """Stands in for a scanner and records what it was asked to scan."""

    seen: ClassVar[dict[str, list[str] | None]] = {}

    def __init__(self, name: str, findings: list[Finding]) -> None:
        self.name, self.findings = name, findings

    def enabled(self, config: Any) -> bool:
        return True

    def run(self, ctx: ScanContext) -> ScannerOutcome:
        Recorder.seen[self.name] = ctx.files
        mine = [x for x in self.findings if ctx.files is None or x.location.path in ctx.files]
        return ScannerOutcome(ToolRun(name=self.name, status=ToolStatus.OK, findings=len(mine)), mine)


def test_incremental_scan_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    write(repo, "app.py", "print(1)\n")
    write(repo, "lib.py", "print(2)\n")
    sem = [f("semgrep", "app.py", "sqli"), f("semgrep", "lib.py", "xss")]
    monkeypatch.setattr(
        pipeline, "SCANNERS", {"semgrep": Recorder("semgrep", sem), "gitleaks": Recorder("gitleaks", [])}
    )
    opts = ScanOptions(offline=True)
    base = scan(repo, Config(), opts, tmp_path / "w1")
    assert Recorder.seen == {"semgrep": None, "gitleaks": None} and len(base.findings) == 2
    (tmp_path / "base.json").write_text(base.model_dump_json(), encoding="utf-8")

    write(repo, "app.py", "print(1)  # edited\n")
    Recorder.seen.clear()
    inc = scan(
        repo,
        Config(),
        ScanOptions(offline=True, compare=tmp_path / "base.json", incremental=True),
        tmp_path / "w2",
    )
    assert Recorder.seen == {"semgrep": ["app.py"], "gitleaks": None}
    assert sorted(x.fingerprint for x in inc.findings) == sorted(x.fingerprint for x in base.findings)
    assert inc.comparison is not None and inc.comparison.new_findings == 0
    assert inc.metadata["incremental"]["changed_files"] == 1

    Recorder.seen.clear()  # nothing changed at all: semgrep and gitleaks are not run
    again = scan(
        repo,
        Config(),
        ScanOptions(offline=True, compare=tmp_path / "base.json", incremental=True),
        tmp_path / "w3",
    )
    assert "semgrep" in Recorder.seen  # app.py still differs from the base
    (tmp_path / "base.json").write_text(again.model_dump_json(), encoding="utf-8")
    Recorder.seen.clear()
    last = scan(
        repo,
        Config(),
        ScanOptions(offline=True, compare=tmp_path / "base.json", incremental=True),
        tmp_path / "w4",
    )
    assert Recorder.seen == {} and len(last.findings) == 2
    assert all(t.status is ToolStatus.REUSED for t in last.tools)
    assert not last.warnings  # reusing findings is normal, not a warning
    md = markdown.render(last)
    assert "semgrep (reused, 2)" in md


def test_rescanned_member_of_a_carried_cluster_is_not_duplicated(tmp_path: Path) -> None:
    fresh = f("trivy", "main.tf", "AVD")
    carried = f("checkov", "main.tf", "public-bucket")
    carried.fingerprints = [carried.fingerprint, fingerprint_of(fresh)]  # as dedupe recorded it
    result = pipeline.process([fresh], [], Config(), tmp_path, ScanOptions(offline=True), carried=[carried])
    assert [x.fingerprint for x in result.findings] == ["checkov:main.tf:public-bucket"]
