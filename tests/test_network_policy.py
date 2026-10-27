"""NetworkPolicy decides what a foothold inside the cluster can reach."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from tests.test_entry_points import cfg, write

PODS = """apiVersion: apps/v1
kind: Deployment
metadata: {name: db-api, namespace: shop}
spec:
  template:
    metadata: {labels: {app: db-api}}
    spec: {containers: [{name: c, image: shop/db-api:1}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: shop}
spec:
  template:
    metadata: {labels: {app: frontend}}
    spec: {containers: [{name: c, image: shop/frontend:1}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: batch, namespace: jobs}
spec:
  template:
    metadata: {labels: {app: batch}}
    spec: {containers: [{name: c, image: jobs/batch:1}]}
---
apiVersion: v1
kind: Namespace
metadata: {name: jobs, labels: {team: data}}
"""
DB, FRONT, BATCH = "k8s:workload:shop/db-api", "k8s:workload:shop/frontend", "k8s:workload:jobs/batch"


def edges(tmp: Path, policy: str) -> dict[tuple[str, str], list[str]]:
    write(tmp, "k8s/pods.yaml", PODS + ("---\n" + policy if policy else ""))
    graph = build_attack_graph(tmp, [], cfg("cluster")).graph
    return {(e.src, e.dst): [r.value for r in e.requires] for e in graph.edges if e.dst in (DB, FRONT, BATCH)}


def test_no_policy_every_pod_is_reachable(tmp_path: Path) -> None:
    e = edges(tmp_path, "")
    assert all(("entry:cluster", w) in e for w in (DB, FRONT, BATCH))


def test_default_deny_cuts_the_pod_off(tmp_path: Path) -> None:
    e = edges(
        tmp_path,
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny, namespace: shop}\n"
        "spec: {podSelector: {}, policyTypes: [Ingress]}\n",
    )
    assert not [k for k in e if k[1] in (DB, FRONT)]
    assert ("entry:cluster", BATCH) in e  # other namespace, no policy


def test_allowed_peers_need_control_first(tmp_path: Path) -> None:
    e = edges(
        tmp_path,
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: db-ingress, namespace: shop}\n"
        "spec:\n  podSelector: {matchLabels: {app: db-api}}\n  ingress:\n"
        "    - from: [{podSelector: {matchLabels: {app: frontend}}}]\n"
        "    - from: [{namespaceSelector: {matchLabels: {team: data}}}]\n",
    )
    assert ("entry:cluster", DB) not in e
    assert e[(FRONT, DB)] == ["code_execution", "vulnerable_dependency"]
    assert e[(BATCH, DB)] == ["code_execution", "vulnerable_dependency"]  # via the namespace label
    assert ("entry:cluster", FRONT) in e  # not selected by the policy


def test_allow_all_rule_keeps_the_pod_reachable(tmp_path: Path) -> None:
    e = edges(
        tmp_path,
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: open, namespace: shop}\n"
        "spec:\n  podSelector: {matchLabels: {app: db-api}}\n  ingress: [{from: [{namespaceSelector: {}}]}]\n",
    )
    assert ("entry:cluster", DB) in e


def test_internet_paths_are_unchanged(tmp_path: Path) -> None:
    write(tmp_path, "k8s/pods.yaml", PODS)
    assert build_attack_graph(tmp_path, [], Config()).paths == []
