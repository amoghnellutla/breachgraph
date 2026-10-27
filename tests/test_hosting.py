"""Hosting-platform configs as real entry points for application repositories."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from tests.test_app_assets import FLASK, SQLI
from tests.test_entry_points import write

RENDER = """services:
  - type: web
    name: shop-api
    rootDir: api
  - type: worker
    name: mailer
    rootDir: worker
"""


def exposed(tmp: Path) -> set[str]:
    graph = build_attack_graph(tmp, [], Config()).graph
    return {e.dst for e in graph.edges if e.src == "internet"}


def test_render_web_service_is_public_and_reaches_the_database(tmp_path: Path) -> None:
    write(tmp_path, "render.yaml", RENDER)
    write(tmp_path, "api/app.py", FLASK)
    write(tmp_path, "worker/run.py", "print('mail')\n")
    sqli = SQLI.model_copy(update={"location": SQLI.location.model_copy(update={"path": "api/app.py"})})
    res = build_attack_graph(tmp_path, [sqli], Config())
    assert "hosting:render:shop-api" in {e.dst for e in res.graph.edges if e.src == "internet"}
    assert "hosting:render:mailer" in res.graph.nodes and "app:application" not in res.graph.nodes
    route = [p.nodes for p in res.paths]
    assert route and route[0][:2] == ["internet", "hosting:render:shop-api"]
    assert route[0][-1] == "app:database:sqlalchemy"


def test_each_platform(tmp_path: Path) -> None:
    write(tmp_path, "site/vercel.json", "{}")
    write(tmp_path, "web/netlify.toml", '[build]\nbase = "frontend"\n')
    write(tmp_path, "edge/fly.toml", 'app = "edge-proxy"\n[http_service]\ninternal_port = 8080\n')
    write(tmp_path, "jobs/fly.toml", 'app = "batch"\n')
    write(tmp_path, "legacy/Procfile", "web: gunicorn app:app\nworker: celery -A app\n")
    write(tmp_path, "gae/app.yaml", "runtime: python312\nservice: api\n")
    write(tmp_path, "k8s/app.yaml", "apiVersion: v1\nkind: Service\nmetadata: {name: x}\nruntime: no\n")
    assert exposed(tmp_path) == {
        "hosting:vercel:site",
        "hosting:netlify:web",
        "hosting:fly:edge-proxy",
        "hosting:procfile:legacy",
        "hosting:app-engine:api",
    }
    graph = build_attack_graph(tmp_path, [], Config()).graph
    assert graph.nodes["hosting:netlify:web"].attrs["code_paths"] == ["web/frontend"]
    assert "hosting:fly:batch" in graph.nodes  # deployed, but nothing public


def test_broken_config_is_a_blind_spot(tmp_path: Path) -> None:
    write(tmp_path, "fly.toml", "app = \n")
    assert any("fly.toml" in s for s in build_attack_graph(tmp_path, [], Config()).skipped)
