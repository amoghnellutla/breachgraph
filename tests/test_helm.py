"""Helm charts are rendered and analyzed like plain manifests, or reported as blind spots."""

import os
import shutil
from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import Graph, NodeKind
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import KubernetesSource, _subchart
from tests.test_entry_points import write

HELM = os.environ.get("BREACHGRAPH_HELM_BIN") or shutil.which("helm")


def chart(root: Path) -> None:
    write(root, "deploy/shop/Chart.yaml", "apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    write(root, "deploy/shop/values.yaml", "image: shop/api:1\nprivileged: true\nport: 8080\n")
    write(
        root,
        "deploy/shop/templates/deployment.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-api
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers:
        - name: api
          image: {{ .Values.image }}
          securityContext:
            privileged: {{ .Values.privileged }}
""",
    )
    write(
        root,
        "deploy/shop/templates/service.yaml",
        """apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-api
spec:
  type: LoadBalancer
  selector: {app: api}
  ports: [{port: {{ .Values.port }}}]
""",
    )


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_chart_is_rendered(tmp_path: Path) -> None:
    chart(tmp_path)
    res = build_attack_graph(tmp_path, [], Config())
    node = res.graph.nodes["k8s:workload:default/breachgraph-api"]
    assert node.evidence[0].path == "deploy/shop/templates/deployment.yaml"
    assert any(w.cls.value == "container_escape" for w in node.weaknesses)
    assert "k8s:workload:default/breachgraph-api" in {e.dst for e in res.graph.edges}
    assert not [s for s in res.skipped if "deploy/shop" in s]


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_chart_that_fails_to_render_is_a_blind_spot(tmp_path: Path) -> None:
    chart(tmp_path)
    write(
        tmp_path,
        "deploy/shop/templates/bad.yaml",
        'kind: x\nmetadata: {{ required "set me" .Values.missing }}\n',
    )
    res = build_attack_graph(tmp_path, [], Config())
    assert [s for s in res.skipped if "deploy/shop" in s] == [
        s for s in res.skipped if s.startswith("deploy/shop: helm template failed") and "set me" in s
    ]
    assert len([s for s in res.skipped if "deploy/shop" in s]) == 1  # the chart, not each template


def test_without_helm_charts_are_blind_spots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chart(tmp_path)
    monkeypatch.setenv("BREACHGRAPH_HELM_BIN", "")
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    res = build_attack_graph(tmp_path, [], Config())
    assert [s for s in res.skipped if "deploy/shop" in s] == [
        "deploy/shop: Helm chart not rendered (install helm to analyze it)"
    ]


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_chart_is_rendered_with_configured_values(tmp_path: Path) -> None:
    chart(tmp_path)
    write(tmp_path, "deploy/shop/values.yaml", "image: shop/api:1\nprivileged: false\nport: 8080\n")
    write(tmp_path, "deploy/values-prod.yaml", "privileged: true\n")
    plain = build_attack_graph(tmp_path, [], Config())
    weak = plain.graph.nodes["k8s:workload:default/breachgraph-api"].weaknesses
    assert not any(w.cls.value == "container_escape" for w in weak)

    config = Config.model_validate(
        {"attack_graph": {"helm_values": {"./deploy/shop/": ["deploy/values-prod.yaml"], "nope": []}}}
    )
    prod = build_attack_graph(tmp_path, [], config)
    weak = prod.graph.nodes["k8s:workload:default/breachgraph-api"].weaknesses
    assert any(w.cls.value == "container_escape" for w in weak)
    assert "nope: attack_graph.helm_values names a directory with no Helm chart" in prod.skipped


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_values_files_must_be_inside_the_tree(tmp_path: Path) -> None:
    chart(tmp_path)
    config = Config.model_validate({"attack_graph": {"helm_values": {"deploy/shop": ["../secret.yaml"]}}})
    res = build_attack_graph(tmp_path, [], config)
    assert (
        "deploy/shop: Helm chart not rendered: values file ../secret.yaml is outside the scanned directory"
        in (res.skipped)
    )


def app(root: Path, where: str, extra: str = "") -> None:
    write(root, f"{where}/Chart.yaml", f"apiVersion: v2\nname: shop\nversion: 0.1.0\n{extra}")
    write(
        root,
        f"{where}/templates/deployment.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-api
spec:
  template:
    metadata:
      labels: {app: api}
    spec:
      containers:
        - name: api
          image: shop/api:1
""",
    )


def render(root: Path) -> tuple[Graph, list[str]]:
    g = Graph()
    ctx = SourceContext(root=root, exclude=[])
    KubernetesSource().collect(ctx, g)
    return g, ctx.skipped


@pytest.mark.skipif(not HELM, reason="helm not installed")
def test_a_directory_named_charts_is_not_a_parent_chart(tmp_path: Path) -> None:
    app(tmp_path, "deployment/helm/charts/shop")
    g, skipped = render(tmp_path)
    assert any(n.kind is NodeKind.WORKLOAD for n in g.nodes.values())
    assert not skipped


def test_a_real_subchart_renders_with_its_parent() -> None:
    assert _subchart("deploy/shop/charts/redis", {"deploy/shop", "deploy/shop/charts/redis"})
    assert not _subchart("charts/shop", {"charts/shop"})
    assert _subchart("charts/redis", {"", "charts/redis"})  # the chart is the repository


@pytest.mark.skipif(not HELM, reason="helm not installed")
def test_a_chart_renders_without_dependencies_that_are_not_committed(tmp_path: Path) -> None:
    deps = "dependencies:\n  - name: redis\n    version: 1.0.0\n    repository: https://example.com\n"
    app(tmp_path, "deploy/shop", deps)
    g, skipped = render(tmp_path)
    assert any(n.kind is NodeKind.WORKLOAD for n in g.nodes.values())
    assert skipped == ["deploy/shop: rendered without its dependencies (redis)"]


@pytest.mark.skipif(not HELM, reason="helm not installed")
def test_a_library_chart_deploys_nothing_and_is_no_blind_spot(tmp_path: Path) -> None:
    write(tmp_path, "lib/Chart.yaml", "apiVersion: v2\nname: lib\nversion: 0.1.0\ntype: library\n")
    assert render(tmp_path)[1] == []
