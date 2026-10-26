"""Kubernetes manifests -> workloads, exposure (Ingress / LoadBalancer / NodePort), service
accounts (incl. EKS IRSA and GKE Workload Identity links), mounted secrets and container-isolation weaknesses.

Helm templates and Kustomize overlays are not rendered here; render them first
(`helm template`, `kustomize build`) and scan the output. Unrendered templates are reported
as skipped so the gap is visible.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
    READ_FILES,
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    Weakness,
    WeaknessClass,
    internet,
)
from breachgraph.graph.sources.common import SourceContext, line_of

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
# hostPath mounts that hand over the node: container runtime socket, root fs, kubelet state.
SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/root",
    "/var/run",
    "/var/run/docker.sock",
    "/run/containerd",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/proc",
    "/sys",
    "/home",
    "/var/log",
)
ESCAPE_CAPS = {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "BPF",
    "ALL",
}
INTERNAL_LB_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-internal": {"true", "0.0.0.0/0"},
    "service.beta.kubernetes.io/aws-load-balancer-scheme": {"internal"},
    "networking.gke.io/load-balancer-type": {"internal"},
    "service.beta.kubernetes.io/azure-load-balancer-internal": {"true"},
}
INTERNAL_INGRESS_ANNOTATIONS = {
    "alb.ingress.kubernetes.io/scheme": {"internal"},
    "kubernetes.io/ingress.class": {"internal", "nginx-internal"},
}
IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
GKE_WI_ANNOTATION = "iam.gke.io/gcp-service-account"
ROLE_ARN_RE = re.compile(r"arn:aws[\w-]*:iam::[^:]*:role/(?:.*/)?([\w+=,.@-]+)$")


def wid(ns: str, name: str) -> str:
    return f"k8s:workload:{ns}/{name}"


def _pod_spec(kind: str, doc: dict[str, Any]) -> dict[str, Any]:
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _pod_labels(kind: str, doc: dict[str, Any]) -> dict[str, str]:
    if kind == "Pod":
        return (doc.get("metadata") or {}).get("labels") or {}
    spec = doc.get("spec") or {}
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("metadata") or {}).get("labels") or {}


class KubernetesSource:
    name = "kubernetes"

    def __init__(self) -> None:
        self.services: list[tuple[dict[str, Any], Evidence]] = []
        self.ingresses: list[tuple[dict[str, Any], Evidence]] = []
        self.service_accounts: dict[str, tuple[dict[str, Any], Evidence]] = {}
        self.workloads: list[tuple[str, dict[str, Any], dict[str, str], Evidence]] = []
        self.roles: dict[str, tuple[dict[str, Any], Evidence]] = {}  # "Role:ns/name" | "ClusterRole:name"
        self.bindings: list[tuple[dict[str, Any], Evidence]] = []

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        for path in ctx.files(".yaml", ".yml"):
            text = ctx.read(path)
            if not text or "apiVersion" not in text or "kind" not in text:
                continue
            rel = ctx.rel(path)
            if "{{" in text:
                ctx.skipped.append(f"{rel}: unrendered Helm/Go template (run `helm template` first)")
                continue
            try:
                docs = list(yaml.safe_load_all(text))
            except yaml.YAMLError:
                ctx.skipped.append(f"{rel}: invalid YAML")
                continue
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                items = doc.get("items") if doc.get("kind") == "List" else [doc]
                for item in items or []:
                    if isinstance(item, dict):
                        self._index(item, rel, text)
        self._build(graph)

    def _index(self, doc: dict[str, Any], rel: str, text: str) -> None:
        kind = str(doc.get("kind", ""))
        meta = doc.get("metadata") or {}
        name = str(meta.get("name", "unnamed"))
        ev = Evidence(
            path=rel,
            line=line_of(text, f"name: {name}"),
            detail=f"{kind} {name}",
            source="kubernetes",
        )
        if kind in WORKLOAD_KINDS:
            self.workloads.append((kind, doc, _pod_labels(kind, doc), ev))
        elif kind == "Service":
            self.services.append((doc, ev))
        elif kind == "Ingress":
            self.ingresses.append((doc, ev))
        elif kind == "ServiceAccount":
            self.service_accounts[f"{meta.get('namespace', 'default')}/{name}"] = (doc, ev)
        elif kind == "Role":
            self.roles[f"Role:{meta.get('namespace', 'default')}/{name}"] = (doc, ev)
        elif kind == "ClusterRole":
            self.roles[f"ClusterRole:{name}"] = (doc, ev)
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            self.bindings.append((doc, ev))

    # ------------------------------------------------------------------ graph

    def _build(self, graph: Graph) -> None:
        by_ns_labels: list[tuple[str, dict[str, str], str]] = []
        for kind, doc, labels, ev in self.workloads:
            meta = doc.get("metadata") or {}
            ns = str(meta.get("namespace", "default"))
            node_id = self._workload(graph, kind, ns, doc, ev)
            by_ns_labels.append((ns, labels, node_id))

        def select(ns: str, selector: dict[str, str]) -> list[str]:
            if not selector:
                return []
            return [
                node_id
                for wns, labels, node_id in by_ns_labels
                if wns == ns and all(labels.get(k) == v for k, v in selector.items())
            ]

        services: dict[str, list[str]] = {}
        for doc, ev in self.services:
            meta, spec = doc.get("metadata") or {}, doc.get("spec") or {}
            ns = str(meta.get("namespace", "default"))
            targets = select(ns, spec.get("selector") or {})
            services[f"{ns}/{meta.get('name')}"] = targets
            stype = spec.get("type", "ClusterIP")
            annotations = meta.get("annotations") or {}
            internal = any(
                str(annotations.get(k, "")).lower() in vals for k, vals in INTERNAL_LB_ANNOTATIONS.items()
            )
            if stype in ("LoadBalancer", "NodePort") and not internal:
                ports = [p.get("port") for p in spec.get("ports") or []]
                self._expose(
                    graph,
                    f"k8s:service:{ns}/{meta.get('name')}",
                    f"Service {meta.get('name')} ({stype})",
                    targets,
                    ev,
                    {"type": stype, "ports": ports},
                    Confidence.HIGH if stype == "LoadBalancer" else Confidence.MEDIUM,
                    "NodePort is internet-facing only if nodes have public IPs/open security groups"
                    if stype == "NodePort"
                    else "",
                )

        for doc, ev in self.ingresses:
            meta, spec = doc.get("metadata") or {}, doc.get("spec") or {}
            ns = str(meta.get("namespace", "default"))
            annotations = meta.get("annotations") or {}
            cls = str(spec.get("ingressClassName") or "")
            internal = cls.endswith("internal") or any(
                str(annotations.get(k, "")).lower() in vals
                for k, vals in INTERNAL_INGRESS_ANNOTATIONS.items()
            )
            if internal:
                continue
            targets = []
            backends = [spec.get("defaultBackend") or {}]
            for rule in spec.get("rules") or []:
                for p in ((rule.get("http") or {}).get("paths")) or []:
                    backends.append(p.get("backend") or {})
            for b in backends:
                svc = (b.get("service") or {}).get("name") or b.get("serviceName")
                if svc:
                    targets += services.get(f"{ns}/{svc}", [])
            hosts = [r.get("host") for r in spec.get("rules") or [] if r.get("host")]
            self._expose(
                graph,
                f"k8s:ingress:{ns}/{meta.get('name')}",
                f"Ingress {meta.get('name')}",
                sorted(set(targets)),
                ev,
                {"hosts": hosts, "tls": bool(spec.get("tls"))},
                Confidence.HIGH,
                "",
            )

        self._rbac(graph, by_ns_labels)

    # ------------------------------------------------------------------ RBAC

    def _rbac(self, graph: Graph, workloads: list[tuple[str, dict[str, str], str]]) -> None:
        """What each service account token can do against the Kubernetes API."""
        for doc, ev in self.bindings:
            meta = doc.get("metadata") or {}
            cluster_wide = doc.get("kind") == "ClusterRoleBinding"
            bns = str(meta.get("namespace", "default"))
            ref = doc.get("roleRef") or {}
            rkind, rname = ref.get("kind"), ref.get("name")
            if rkind == "ClusterRole" and rname == "cluster-admin":
                rules: list[dict[str, Any]] = [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]
            else:
                key = f"ClusterRole:{rname}" if rkind == "ClusterRole" else f"Role:{bns}/{rname}"
                rules = (self.roles.get(key, ({}, ev))[0].get("rules")) or []
            scope = "*" if cluster_wide else bns
            for subj in doc.get("subjects") or []:
                if subj.get("kind") != "ServiceAccount":
                    continue
                said = f"k8s:serviceaccount:{subj.get('namespace', bns)}/{subj.get('name')}"
                if said not in graph.nodes:
                    continue
                for rule in rules:
                    self._rule_edges(graph, said, rule, scope, ev, workloads)

    def _rule_edges(
        self,
        graph: Graph,
        said: str,
        rule: dict[str, Any],
        scope: str,
        ev: Evidence,
        workloads: list[tuple[str, dict[str, str], str]],
    ) -> None:
        verbs = {str(v) for v in rule.get("verbs") or []}
        resources = {str(r) for r in rule.get("resources") or []}
        anyres = "*" in resources
        where = "the whole cluster" if scope == "*" else f"namespace {scope}"
        if (anyres or "secrets" in resources) and verbs & {"get", "list", "watch", "*"}:
            sid = f"k8s:secrets:{scope}"
            graph.add_node(
                Node(
                    id=sid,
                    kind=NodeKind.SECRET,
                    name=f"All Secrets in {where}",
                    value=8,
                    evidence=[ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=said,
                    dst=sid,
                    kind=EdgeKind.CAN_ACCESS,
                    evidence=[ev],
                    note=f"RBAC grants {'/'.join(sorted(verbs))} on secrets",
                )
            )
        execs = (anyres or "pods/exec" in resources) and verbs & {"create", "*"}
        creates = (anyres or {"pods", "deployments", "daemonsets", "jobs"} & resources) and verbs & {
            "create",
            "patch",
            "update",
            "*",
        }
        if execs or creates:
            how = "exec into pods" if execs else "create or modify workloads"
            for wns, _labels, wid_ in workloads:
                if scope in ("*", wns) and wid_ != said:
                    graph.add_edge(
                        Edge(
                            src=said,
                            dst=wid_,
                            kind=EdgeKind.COMPROMISES,
                            evidence=[ev],
                            confidence=Confidence.MEDIUM,
                            note=f"RBAC allows this token to {how} in {where}",
                        )
                    )
        if creates:
            # Creating pods normally means a privileged pod can be scheduled -> node takeover,
            # unless Pod Security Admission blocks it (not visible from manifests alone).
            host_id = "k8s:host:nodes"
            graph.add_node(
                Node(id=host_id, kind=NodeKind.HOST, name="Kubernetes worker nodes", evidence=[ev])
            )
            graph.add_edge(
                Edge(
                    src=said,
                    dst=host_id,
                    kind=EdgeKind.RUNS_ON,
                    evidence=[ev],
                    confidence=Confidence.LOW,
                    note=(
                        "can create pods; a privileged pod reaches the node unless "
                        "Pod Security Admission enforces 'restricted'"
                    ),
                )
            )

    def _expose(
        self,
        graph: Graph,
        node_id: str,
        name: str,
        targets: list[str],
        ev: Evidence,
        attrs: dict[str, object],
        confidence: Confidence,
        note: str,
    ) -> None:
        graph.add_node(internet())
        graph.add_node(Node(id=node_id, kind=NodeKind.ENTRYPOINT, name=name, attrs=attrs, evidence=[ev]))
        graph.add_edge(
            Edge(
                src=INTERNET_ID,
                dst=node_id,
                kind=EdgeKind.EXPOSES,
                confidence=confidence,
                evidence=[ev],
                note=note,
            )
        )
        for t in targets:
            graph.add_edge(
                Edge(src=node_id, dst=t, kind=EdgeKind.EXPOSES, confidence=confidence, evidence=[ev])
            )

    def _workload(self, graph: Graph, kind: str, ns: str, doc: dict[str, Any], ev: Evidence) -> str:
        meta = doc.get("metadata") or {}
        name = str(meta.get("name", "unnamed"))
        spec = _pod_spec(kind, doc)
        containers = [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]
        node = graph.add_node(
            Node(
                id=wid(ns, name),
                kind=NodeKind.WORKLOAD,
                name=f"{kind} {ns}/{name}",
                attrs={
                    "platform": "kubernetes",
                    "namespace": ns,
                    "images": [c.get("image") for c in containers if c.get("image")],
                    "host_network": bool(spec.get("hostNetwork")),
                },
                evidence=[ev],
            )
        )

        # --- isolation weaknesses (each is a container-to-node escape condition)
        reasons: list[str] = []
        if spec.get("hostPID"):
            reasons.append("hostPID: true")
        if spec.get("hostIPC"):
            reasons.append("hostIPC: true")
        for c in containers:
            sc = c.get("securityContext") or {}
            if sc.get("privileged"):
                reasons.append(f"container {c.get('name')} is privileged")
            caps = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
            if caps & ESCAPE_CAPS:
                reasons.append(f"container {c.get('name')} adds {', '.join(sorted(caps & ESCAPE_CAPS))}")
        mounted = {v.get("name"): v for v in spec.get("volumes") or []}
        for v in mounted.values():
            hp = (v.get("hostPath") or {}).get("path")
            if hp and any(
                hp.rstrip("/") == s.rstrip("/") or (s != "/" and hp.startswith(s + "/"))
                for s in SENSITIVE_HOST_PATHS
            ):
                reasons.append(f"mounts host path {hp}")
        for r in reasons:
            node.weaknesses.append(Weakness(cls=WeaknessClass.CONTAINER_ESCAPE, title=r, evidence=ev))
        if spec.get("hostNetwork"):
            node.weaknesses.append(
                Weakness(
                    cls=WeaknessClass.METADATA_REACHABLE,
                    title=(
                        "hostNetwork: pod shares the node network, so the node's "
                        "cloud metadata endpoint is reachable"
                    ),
                    evidence=ev,
                )
            )
        if reasons:
            host_id = "k8s:host:nodes"
            graph.add_node(
                Node(id=host_id, kind=NodeKind.HOST, name="Kubernetes worker nodes", evidence=[ev])
            )
            graph.add_edge(
                Edge(
                    src=node.id,
                    dst=host_id,
                    kind=EdgeKind.RUNS_ON,
                    requires=[WeaknessClass.CONTAINER_ESCAPE],
                    evidence=[ev],
                    note="container isolation is disabled: " + "; ".join(reasons),
                )
            )

        # --- images
        for c in containers:
            if c.get("image"):
                img = str(c["image"])
                graph.add_node(Node(id=f"image:{img}", kind=NodeKind.IMAGE, name=img, evidence=[ev]))
                graph.add_edge(Edge(src=node.id, dst=f"image:{img}", kind=EdgeKind.RUNS_IMAGE, evidence=[ev]))

        # --- secrets the workload can read
        secret_refs: set[str] = set()
        for v in mounted.values():
            if (v.get("secret") or {}).get("secretName"):
                secret_refs.add(v["secret"]["secretName"])
            for src in ((v.get("projected") or {}).get("sources")) or []:
                if (src.get("secret") or {}).get("name"):
                    secret_refs.add(src["secret"]["name"])
        for c in containers:
            for env in c.get("env") or []:
                ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
                if ref:
                    secret_refs.add(ref)
            for env_from in c.get("envFrom") or []:
                ref = (env_from.get("secretRef") or {}).get("name")
                if ref:
                    secret_refs.add(ref)
        for s in sorted(secret_refs):
            sid = f"k8s:secret:{ns}/{s}"
            graph.add_node(
                Node(id=sid, kind=NodeKind.SECRET, name=f"Secret {ns}/{s}", value=6, evidence=[ev])
            )
            graph.add_edge(
                Edge(src=node.id, dst=sid, kind=EdgeKind.MOUNTS, requires=READ_FILES, evidence=[ev])
            )

        # --- identity: service account token, and the cloud role it maps to (IRSA)
        sa = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
        automount = spec.get("automountServiceAccountToken")
        sa_doc, sa_ev = self.service_accounts.get(f"{ns}/{sa}", ({}, ev))
        if automount is None:
            automount = sa_doc.get("automountServiceAccountToken", True)
        annotations = (sa_doc.get("metadata") or {}).get("annotations") or {}
        role_arn = annotations.get(IRSA_ANNOTATION)
        gcp_sa = annotations.get(GKE_WI_ANNOTATION)
        if automount is not False or role_arn or gcp_sa:
            said = f"k8s:serviceaccount:{ns}/{sa}"
            graph.add_node(
                Node(
                    id=said,
                    kind=NodeKind.IDENTITY,
                    name=f"ServiceAccount {ns}/{sa}",
                    attrs={"platform": "kubernetes"},
                    evidence=[sa_ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=node.id,
                    dst=said,
                    kind=EdgeKind.USES_IDENTITY,
                    requires=CONTROL,
                    evidence=[ev],
                    note="using the pod's token/role requires running code in the pod",
                )
            )
            if role_arn:
                m = ROLE_ARN_RE.search(str(role_arn))
                role_name = m.group(1) if m else str(role_arn)
                rid = f"aws:iam_role:{role_name}"
                graph.add_node(
                    Node(
                        id=rid,
                        kind=NodeKind.IDENTITY,
                        name=f"IAM role {role_name}",
                        attrs={"platform": "aws"},
                        evidence=[sa_ev],
                    )
                )
                graph.add_edge(
                    Edge(
                        src=said,
                        dst=rid,
                        kind=EdgeKind.USES_IDENTITY,
                        evidence=[sa_ev],
                        note="EKS IRSA annotation",
                    )
                )
            if gcp_sa:
                gid = f"gcp:service_account:{str(gcp_sa).split('@', 1)[0]}"
                graph.add_node(
                    Node(
                        id=gid,
                        kind=NodeKind.IDENTITY,
                        name=f"Service account {gcp_sa}",
                        attrs={"platform": "gcp"},
                        evidence=[sa_ev],
                    )
                )
                graph.add_edge(
                    Edge(
                        src=said,
                        dst=gid,
                        kind=EdgeKind.USES_IDENTITY,
                        evidence=[sa_ev],
                        confidence=Confidence.MEDIUM,
                        note="GKE Workload Identity annotation (also needs roles/iam.workloadIdentityUser)",
                    )
                )
        return node.id
