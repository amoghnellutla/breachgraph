"""RBAC grants that look narrow and turn into more. Attack classes as documented by KubeHound."""

from pathlib import Path

import pytest
import yaml

from breachgraph.graph.model import Confidence, Graph
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import KubernetesSource

SA = "k8s:serviceaccount:default/ci"
OTHER = "k8s:serviceaccount:default/payments"


def pod(name: str) -> dict:  # type: ignore[type-arg]
    labels = {"app": name}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {"serviceAccountName": name, "containers": [{"name": "c", "image": "x:1"}]},
            },
        },
    }


def cluster(tmp: Path, rules: list[dict], kind: str = "ClusterRole") -> Graph:  # type: ignore[type-arg]
    binding = "ClusterRoleBinding" if kind == "ClusterRole" else "RoleBinding"
    docs = [
        pod("ci"),
        pod("payments"),
        {
            "apiVersion": "rbac/v1",
            "kind": kind,
            "metadata": {"name": "r", "namespace": "default"},
            "rules": rules,
        },
        {
            "apiVersion": "rbac/v1",
            "kind": binding,
            "metadata": {"name": "b", "namespace": "default"},
            "roleRef": {"kind": kind, "name": "r"},
            "subjects": [{"kind": "ServiceAccount", "name": "ci", "namespace": "default"}],
        },
    ]
    (tmp / "all.yaml").write_text(yaml.safe_dump_all(docs), encoding="utf-8")
    g = Graph()
    KubernetesSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def rule(verbs: list[str], *resources: str) -> dict:  # type: ignore[type-arg]
    return {"apiGroups": ["*"], "verbs": verbs, "resources": list(resources)}


def edge(g: Graph, dst: str):  # type: ignore[no-untyped-def]
    return next((e for e in g.edges if e.src == SA and e.dst == dst), None)


ADMIN = "k8s:admin:*"


def test_writing_a_binding_alone_is_stopped_by_the_api_server(tmp_path: Path) -> None:
    assert not edge(cluster(tmp_path, [rule(["create"], "clusterrolebindings")]), ADMIN)


def test_bind_with_a_binding_takes_over(tmp_path: Path) -> None:
    rules = [rule(["bind"], "clusterroles"), rule(["create"], "clusterrolebindings")]
    assert edge(cluster(tmp_path, rules), ADMIN)


def test_bind_with_nothing_to_write_a_binding_with_is_no_move(tmp_path: Path) -> None:
    assert not edge(cluster(tmp_path, [rule(["bind"], "clusterroles")]), ADMIN)


def test_escalate_needs_a_role_it_can_edit(tmp_path: Path) -> None:
    assert not edge(cluster(tmp_path, [rule(["escalate"], "clusterroles")]), ADMIN)
    rules = [rule(["escalate", "update"], "clusterroles")]
    assert edge(cluster(tmp_path, rules), ADMIN)


@pytest.mark.parametrize("resource", ["users", "groups", "serviceaccounts"])
def test_impersonation_takes_over(tmp_path: Path, resource: str) -> None:
    assert edge(cluster(tmp_path, [rule(["impersonate"], resource)]), ADMIN)


def test_a_namespace_role_only_controls_its_namespace(tmp_path: Path) -> None:
    g = cluster(tmp_path, [rule(["impersonate"], "serviceaccounts")], kind="Role")
    assert edge(g, "k8s:admin:default") and "namespace default" in g.nodes["k8s:admin:default"].name


def test_minting_a_token_reaches_each_service_account_in_scope(tmp_path: Path) -> None:
    g = cluster(tmp_path, [rule(["create"], "serviceaccounts/token")], kind="Role")
    assert edge(g, OTHER)
    assert not edge(g, SA)


def test_reading_tokens_is_not_minting_them(tmp_path: Path) -> None:
    assert not edge(cluster(tmp_path, [rule(["get"], "serviceaccounts/token")]), OTHER)


def test_nodes_proxy_reaches_the_node(tmp_path: Path) -> None:
    step = edge(cluster(tmp_path, [rule(["get"], "nodes/proxy")]), "k8s:host:nodes")
    assert step and step.confidence is Confidence.MEDIUM


@pytest.mark.parametrize("resource", ["pods/attach", "pods/ephemeralcontainers"])
def test_attach_and_debug_containers_are_exec_by_another_name(tmp_path: Path, resource: str) -> None:
    verbs = ["patch"] if "ephemeral" in resource else ["create"]
    workload = "k8s:workload:default/payments"
    g = cluster(tmp_path, [rule(verbs, resource)])
    assert edge(g, workload)
