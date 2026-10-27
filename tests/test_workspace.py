"""Several repositories scanned as one: paths that cross an app repo and an infra repo."""

import shutil
from pathlib import Path

from typer.testing import CliRunner

from breachgraph import workspace
from breachgraph.cli import app
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from tests.test_graph_paths import SSRF

PLATFORM = Path(__file__).parent.parent / "examples" / "vulnerable-platform"


def split(tmp: Path) -> tuple[Path, Path]:
    """The demo platform cut in two, the way many teams keep it: code in one repo, infra in another."""
    app_repo, infra_repo = tmp / "shop-api", tmp / "shop-infra"
    shutil.copytree(PLATFORM / "services", app_repo / "services")
    shutil.copytree(PLATFORM / "k8s", infra_repo / "k8s")
    shutil.copytree(PLATFORM / "infra", infra_repo / "infra")
    return app_repo, infra_repo


def ssrf_at(prefix: str):  # type: ignore[no-untyped-def]
    loc = SSRF.location.model_copy(update={"path": f"{prefix}/{SSRF.location.path}"})
    return SSRF.model_copy(update={"location": loc})


def test_attack_path_crosses_repositories(tmp_path: Path) -> None:
    app_repo, infra_repo = split(tmp_path)
    alone = [build_attack_graph(r, [SSRF], Config()).paths for r in (app_repo, infra_repo)]
    assert alone == [[], []]  # neither repository shows the path on its own

    ws = tmp_path / "ws"
    layout = workspace.build([app_repo, infra_repo], Config().exclude_paths, ws)
    assert list(layout) == ["shop-api", "shop-infra"]
    paths = build_attack_graph(ws, [ssrf_at("shop-api")], Config()).paths
    targets = {p.target.name for p in paths}
    assert "S3 bucket shop-customer-data-prod" in targets


def test_labels_are_unique() -> None:
    assert workspace.labels([Path("/a/app"), Path("/b/app"), Path("/c/app")]) == ["app", "app-2", "app-3"]


def test_cli_scans_several_paths_as_one(tmp_path: Path) -> None:
    app_repo, infra_repo = split(tmp_path)
    res = CliRunner().invoke(
        app,
        [
            "scan",
            str(app_repo),
            str(infra_repo),
            "-o",
            str(tmp_path / "out"),
            "--offline",
            "--no-fail",
            "-f",
            "json",
        ],
    )
    assert res.exit_code == 0, res.output
    assert "Scanning as one: shop-api/" in res.output
    report = (tmp_path / "out" / "breachgraph.json").read_text(encoding="utf-8")
    assert '"project": "shop-api + shop-infra"' in report
    assert not list(tmp_path.glob("breachgraph-workspace-*"))
