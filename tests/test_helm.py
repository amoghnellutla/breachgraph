"""Helm charts are rendered and analyzed like plain manifests, or reported as blind spots."""

import os
import shutil
from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
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
