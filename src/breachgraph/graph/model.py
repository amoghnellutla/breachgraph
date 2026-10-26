"""Asset/exposure graph: what is reachable from the internet, and what each workload can access.

Nodes are assets. Edges are access relationships extracted from code and configuration, each
with evidence (file:line) and a confidence. Scanner findings attach to nodes as *weaknesses*:
an edge marked ``requires`` can only be crossed when the source node carries a weakness of one of
those classes (e.g. moving from "serves a route" to "controls the workload" requires a code
execution weakness on that route). This mirrors how exposure-management products model risk:
a finding matters in proportion to what it exposes.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from enum import StrEnum

from pydantic import BaseModel, Field


class NodeKind(StrEnum):
    INTERNET = "internet"
    ENTRYPOINT = "entrypoint"  # load balancer, ingress, public service, open security group
    WORKLOAD = "workload"  # k8s deployment, compose service, ECS service, Lambda
    IMAGE = "image"
    ROUTE = "route"  # HTTP route served by code
    IDENTITY = "identity"  # IAM role, k8s service account
    DATASTORE = "datastore"  # S3, RDS, DynamoDB...
    SECRET = "secret"  # noqa: S105  k8s secret, Secrets Manager, env credentials
    HOST = "host"  # the node/VM a workload runs on


class EdgeKind(StrEnum):
    EXPOSES = "exposes"  # internet -> entrypoint -> workload
    SERVES = "serves"  # workload -> route
    RUNS_IMAGE = "runs_image"
    COMPROMISES = "compromises"  # route -> workload (needs a weakness)
    USES_IDENTITY = "uses_identity"
    CAN_ACCESS = "can_access"  # identity -> datastore/secret
    MOUNTS = "mounts"  # workload -> secret
    RUNS_ON = "runs_on"  # workload -> host (needs escape conditions)
    CONNECTS_TO = "connects_to"  # workload -> datastore via connection config


class WeaknessClass(StrEnum):
    """Coarse classes of what a weakness lets an outsider do; mapped from CWE/rule metadata."""

    CODE_EXECUTION = "code_execution"  # command injection, deserialization, template injection
    SSRF = "ssrf"
    INJECTION_DATA = "data_injection"  # SQL/NoSQL/LDAP injection
    FILE_READ = "file_read"  # path traversal, XXE
    AUTH_BYPASS = "auth_bypass"
    CREDENTIAL_EXPOSURE = "credential_exposure"  # hardcoded/leaked secret
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"  # known-exploited / high-EPSS CVE in image/deps
    CONTAINER_ESCAPE = "container_escape"  # privileged, hostPath, hostPID, dangerous caps
    METADATA_REACHABLE = "metadata_reachable"  # cloud metadata service reachable from workload


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Weaknesses that let an attacker run code as (i.e. fully control) a workload.
CONTROL = [WeaknessClass.CODE_EXECUTION, WeaknessClass.VULNERABLE_DEPENDENCY]
# Weaknesses that let an attacker read a mounted secret file.
READ_FILES = [*CONTROL, WeaknessClass.FILE_READ]


class Evidence(BaseModel):
    path: str
    line: int | None = None
    detail: str = ""
    source: str = ""  # parser or scanner that produced it

    def label(self) -> str:
        return self.path + (f":{self.line}" if self.line else "")


class Weakness(BaseModel):
    cls: WeaknessClass
    fingerprint: str | None = None  # links back to a Finding
    title: str
    evidence: Evidence


class Node(BaseModel):
    id: str  # stable, e.g. "k8s:deployment:default/web"
    kind: NodeKind
    name: str
    attrs: dict[str, object] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    weaknesses: list[Weakness] = Field(default_factory=list)
    value: int = 0  # 0-10 business value; crown jewels are >= 7

    def has(self, classes: set[WeaknessClass]) -> list[Weakness]:
        return [w for w in self.weaknesses if w.cls in classes]


class Edge(BaseModel):
    src: str
    dst: str
    kind: EdgeKind
    requires: list[WeaknessClass] = Field(default_factory=list)  # any one, on the src node
    confidence: Confidence = Confidence.HIGH
    evidence: list[Evidence] = Field(default_factory=list)
    note: str = ""


class Graph(BaseModel):
    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.attrs.update({k: v for k, v in node.attrs.items() if v is not None})
        existing.evidence.extend(e for e in node.evidence if e not in existing.evidence)
        existing.value = max(existing.value, node.value)
        return existing

    def add_edge(self, edge: Edge) -> None:
        # Edges that need different weaknesses are different ways in (e.g. code execution vs SSRF
        # to the same identity), so they are kept apart.
        key = (edge.src, edge.dst, edge.kind, sorted(edge.requires))
        for e in self.edges:
            if (e.src, e.dst, e.kind, sorted(e.requires)) == key:
                e.evidence.extend(x for x in edge.evidence if x not in e.evidence)
                return
        self.edges.append(edge)

    def out_edges(self) -> dict[str, list[Edge]]:
        adj: dict[str, list[Edge]] = defaultdict(list)
        for e in self.edges:
            if e.src in self.nodes and e.dst in self.nodes:
                adj[e.src].append(e)
        return adj

    def of_kind(self, kind: NodeKind) -> Iterator[Node]:
        return (n for n in self.nodes.values() if n.kind is kind)


INTERNET_ID = "internet"


def internet() -> Node:
    return Node(id=INTERNET_ID, kind=NodeKind.INTERNET, name="Internet")
