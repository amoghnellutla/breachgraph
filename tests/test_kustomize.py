"""Kustomize overlays are built and analyzed as deployed, or reported as blind spots."""

from pathlib import Path

import pytest

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.sources.kubernetes import _kustomize_command
from tests.test_entry_points import write

TOOL = _kustomize_command()


def overlay(root: Path) -> None:
    write(root, "k8s/base/kustomization.yaml", "resources:\n  - deployment.yaml\n  - service.yaml\n")
    write(
        root,
        "k8s/base/deployment.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: shop/api:1
""",
    )
    write(
        root,
        "k8s/base/service.yaml",
        """apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  selector: {app: api}
  ports: [{port: 80}]
""",
    )
    write(
        root,
        "k8s/overlays/prod/kustomization.yaml",
        "namespace: shop\nnamePrefix: prod-\nresources:\n  - ../../base\n  - ingress.yaml\n"
        "patches:\n  - path: privileged.yaml\n",
    )
    write(
        root,
        "k8s/overlays/prod/privileged.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          securityContext: {privileged: true}
""",
    )
    write(
        root,
        "k8s/overlays/prod/ingress.yaml",
        """apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: api, port: {number: 80}}}
""",
    )


def workloads(res) -> set[str]:  # type: ignore[no-untyped-def]
    return {n for n in res.graph.nodes if n.startswith("k8s:workload:")}


@pytest.mark.skipif(TOOL is None, reason="neither kustomize nor kubectl is installed")
def test_overlay_is_built_as_deployed(tmp_path: Path) -> None:
    overlay(tmp_path)
    res = build_attack_graph(tmp_path, [], Config())
    # The patch made it privileged, the overlay moved and renamed it, and the base copy and the
    # partial patch are not indexed as workloads of their own.
    assert workloads(res) == {"k8s:workload:shop/prod-api"}
    node = res.graph.nodes["k8s:workload:shop/prod-api"]
    assert node.evidence[0].path == "k8s/base/deployment.yaml"
    assert any(w.cls.value == "container_escape" for w in node.weaknesses)
    # The ingress the overlay adds reaches the renamed service's pods.
    assert "k8s:workload:shop/prod-api" in {e.dst for e in res.graph.edges}
    assert not [s for s in res.skipped if s.startswith("k8s/")]


@pytest.mark.skipif(TOOL is None, reason="neither kustomize nor kubectl is installed")
def test_failed_build_falls_back_to_the_files(tmp_path: Path) -> None:
    overlay(tmp_path)
    write(tmp_path, "k8s/overlays/prod/kustomization.yaml", "resources:\n  - ../../base\n  - missing.yaml\n")
    res = build_attack_graph(tmp_path, [], Config())
    assert any(s.startswith("k8s/overlays/prod: kustomization build failed") for s in res.skipped)
    assert "k8s:workload:default/api" in workloads(res)


def test_remote_and_outside_resources_are_not_built(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_KUSTOMIZE_BIN", str(tmp_path / "must-not-run"))
    overlay(tmp_path)
    write(
        tmp_path,
        "k8s/overlays/prod/kustomization.yaml",
        "resources:\n  - ../../base\n  - https://github.com/acme/infra//base?ref=v1\n",
    )
    write(tmp_path, "k8s/overlays/dev/kustomization.yaml", "resources:\n  - ../../../../elsewhere\n")
    res = build_attack_graph(tmp_path, [], Config())
    assert "k8s/overlays/prod: kustomization not built: remote resource" in " ".join(res.skipped)
    assert any("k8s/overlays/dev" in s and "outside the scanned directory" in s for s in res.skipped)
    assert "k8s:workload:default/api" in workloads(res)  # the files, as they are


def test_without_a_tool_overlays_are_blind_spots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BREACHGRAPH_KUSTOMIZE_BIN", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)
    overlay(tmp_path)
    res = build_attack_graph(tmp_path, [], Config())
    assert any(s.startswith("k8s/overlays/prod: kustomization not built (install") for s in res.skipped)
    assert not [s for s in res.skipped if s.startswith("k8s/base")]  # included, not a top level
    assert "k8s:workload:default/api" in workloads(res)


def test_templating_outside_modeled_objects_is_not_a_blind_spot(tmp_path: Path) -> None:
    write(
        tmp_path,
        "appsets/list.yaml",
        "apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: x\n"
        "spec:\n  template:\n    metadata:\n      name: '{{cluster}}-guestbook'\n",
    )
    write(
        tmp_path,
        "raw/deploy.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: '{{ name }}'\nspec: {}\n",
    )
    res = build_attack_graph(tmp_path, [], Config())
    assert [s for s in res.skipped if "template syntax" in s] == [
        "raw/deploy.yaml: template syntax ({{ }}) outside a Helm chart, not analyzed"
    ]


def test_tool_errors_keep_the_explanation_and_drop_local_paths(tmp_path: Path) -> None:
    from breachgraph.graph.sources.common import SourceContext
    from breachgraph.graph.sources.kubernetes import _tool_error

    ctx = SourceContext(root=tmp_path, exclude=[])
    helm = (
        "Error: template: apps/templates/a.yaml:12:30: executing\n"
        "  nil pointer evaluating interface {}.namespace\n\nUse --debug flag to render out invalid YAML\n"
    )
    assert _tool_error(helm, ctx) == (
        "template: apps/templates/a.yaml:12:30: executing: nil pointer evaluating interface {}.namespace"
    )
    assert _tool_error(f"error: must build at directory: {tmp_path / 'k8s'}", ctx) == (
        "must build at directory: k8s"
    )
    assert _tool_error("", ctx) == "unknown error"
