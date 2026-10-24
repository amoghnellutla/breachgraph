"""Tests for the attack-graph source parsers (Kubernetes, Terraform, routes, images)."""

from pathlib import Path

import pytest

from breachgraph.graph.model import EdgeKind, Graph, NodeKind, WeaknessClass
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.hcl import decode_policy
from breachgraph.graph.sources.kubernetes import KubernetesSource
from breachgraph.graph.sources.routes import RouteSource
from breachgraph.graph.sources.terraform import TerraformSource


def write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def k8s_graph(tmp: Path, manifest: str) -> Graph:
    write(tmp, "m.yaml", manifest)
    g = Graph()
    KubernetesSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def tf_graph(tmp: Path, hcl: str) -> tuple[Graph, SourceContext]:
    write(tmp, "main.tf", hcl)
    g = Graph()
    ctx = SourceContext(root=tmp, exclude=[])
    TerraformSource().collect(ctx, g)
    return g, ctx


# ------------------------------------------------------------------ Kubernetes


def test_k8s_ingress_exposes_workload(tmp_path: Path) -> None:
    g = k8s_graph(
        tmp_path,
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: default}
spec:
  rules:
    - http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}]}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: default}
spec: {selector: {app: web}, ports: [{port: 80}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: default}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: c, image: web:1}]
""",
    )
    kinds = {n.kind for n in g.nodes.values()}
    assert NodeKind.INTERNET in kinds and NodeKind.ENTRYPOINT in kinds
    exposes = [e for e in g.edges if e.kind is EdgeKind.EXPOSES]
    assert any(e.src == "internet" for e in exposes)
    assert any(e.dst == "k8s:workload:default/web" for e in exposes)


def test_k8s_internal_ingress_not_exposed(tmp_path: Path) -> None:
    g = k8s_graph(
        tmp_path,
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: default
  annotations: {alb.ingress.kubernetes.io/scheme: internal}
spec:
  rules: [{http: {paths: [{backend: {service: {name: web, port: {number: 80}}}}]}}]
""",
    )
    assert not any(e.src == "internet" for e in g.edges)


def test_k8s_privileged_pod_escapes_to_node(tmp_path: Path) -> None:
    g = k8s_graph(
        tmp_path,
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: default}
spec:
  template:
    spec:
      containers: [{name: c, image: web:1, securityContext: {privileged: true}}]
""",
    )
    w = g.nodes["k8s:workload:default/web"]
    assert w.has({WeaknessClass.CONTAINER_ESCAPE})
    assert any(e.kind is EdgeKind.RUNS_ON and e.requires for e in g.edges)


def test_k8s_hostnetwork_marks_metadata_reachable(tmp_path: Path) -> None:
    g = k8s_graph(
        tmp_path,
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: default}
spec:
  template:
    spec:
      hostNetwork: true
      containers: [{name: c, image: web:1}]
""",
    )
    assert g.nodes["k8s:workload:default/web"].has({WeaknessClass.METADATA_REACHABLE})


def test_k8s_identity_edge_requires_compromise(tmp_path: Path) -> None:
    """A pod using a service account must be compromised before the token is usable."""
    g = k8s_graph(
        tmp_path,
        """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: default
  annotations: {eks.amazonaws.com/role-arn: "arn:aws:iam::111122223333:role/pod-role"}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: default}
spec:
  template:
    spec:
      serviceAccountName: api
      containers: [{name: c, image: api:1}]
""",
    )
    edge = next(
        e for e in g.edges if e.src == "k8s:workload:default/api" and e.kind is EdgeKind.USES_IDENTITY
    )
    assert WeaknessClass.CODE_EXECUTION in edge.requires
    # IRSA link to the AWS role is structural (free once you hold the token).
    irsa = next(e for e in g.edges if e.dst == "aws:iam_role:pod-role")
    assert not irsa.requires


def test_k8s_rbac_secret_access(tmp_path: Path) -> None:
    g = k8s_graph(
        tmp_path,
        """
apiVersion: v1
kind: ServiceAccount
metadata: {name: api, namespace: default}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules: [{apiGroups: [""], resources: [secrets], verbs: [get, list]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: b}
roleRef: {kind: ClusterRole, name: secret-reader, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: api, namespace: default}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: default}
spec:
  template:
    spec: {serviceAccountName: api, containers: [{name: c, image: api:1}]}
""",
    )
    assert any(
        e.src == "k8s:serviceaccount:default/api" and g.nodes[e.dst].kind is NodeKind.SECRET for e in g.edges
    )


def test_k8s_unrendered_helm_is_skipped(tmp_path: Path) -> None:
    write(
        tmp_path, "c.yaml", "kind: Deployment\napiVersion: apps/v1\nmetadata:\n  name: {{ .Release.Name }}\n"
    )
    g = Graph()
    ctx = SourceContext(root=tmp_path, exclude=[])
    KubernetesSource().collect(ctx, g)
    assert any("Helm" in s or "template" in s for s in ctx.skipped)


# ------------------------------------------------------------------ Terraform


def test_tf_public_s3_bucket(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_s3_bucket" "b" {
  bucket = "data"
}
resource "aws_s3_bucket_acl" "a" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
""",
    )
    assert any(e.src == "internet" and "s3_bucket" in e.dst for e in g.edges)


def test_tf_blocked_s3_not_public(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_s3_bucket" "b" {
  bucket = "data"
}
resource "aws_s3_bucket_acl" "a" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket             = aws_s3_bucket.b.id
  ignore_public_acls = true
}
""",
    )
    assert not any(e.src == "internet" for e in g.edges)


def test_tf_iam_role_data_access_scoped(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_s3_bucket" "other" {
  bucket = "other"
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.r.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.data.arn}/*" }]
  })
}
""",
    )
    access = [e for e in g.edges if e.kind is EdgeKind.CAN_ACCESS and e.src == "aws:iam_role:r"]
    reached = {e.dst for e in access}
    assert any("data" in d for d in reached)
    assert not any("other" in d for d in reached)  # policy is scoped to the data bucket only


def test_tf_admin_managed_policy_reaches_everything(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.r.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
""",
    )
    assert any(e.src == "aws:iam_role:r" and e.dst == "aws:account-admin" for e in g.edges)


def test_tf_privilege_escalation_detected(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.r.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["iam:AttachRolePolicy"], Resource = "*" }]
  })
}
""",
    )
    edge = next((e for e in g.edges if e.dst == "aws:account-admin"), None)
    assert edge is not None and "escalation" in edge.note


def test_tf_explicit_deny_wins(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.r.id
  policy = jsonencode({
    Statement = [
      { Effect = "Allow", Action = ["s3:*"], Resource = "*" },
      { Effect = "Deny", Action = ["s3:*"], Resource = "*" }
    ]
  })
}
""",
    )
    assert not any(
        e.kind is EdgeKind.CAN_ACCESS and e.src == "aws:iam_role:r" and "data" in e.dst for e in g.edges
    )


def test_tf_open_security_group_exposes_instance(tmp_path: Path) -> None:
    g, _ = tf_graph(
        tmp_path,
        """
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "web" {
  vpc_security_group_ids      = [aws_security_group.sg.id]
  associate_public_ip_address = true
}
""",
    )
    assert any(e.src == "internet" and e.dst == "aws:ec2:web" for e in g.edges)


def test_tf_unparseable_policy_reported(tmp_path: Path) -> None:
    _g, ctx = tf_graph(
        tmp_path,
        """
resource "aws_iam_role" "r" {
  name               = "r"
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.r.id
  policy = var.some_policy
}
""",
    )
    assert any("could not be evaluated" in s for s in ctx.skipped)


def test_decode_policy_jsonencode() -> None:
    doc = decode_policy('${jsonencode({Statement = [{Effect = "Allow", Action = "s3:*"}]})}')
    assert doc is not None and doc["Statement"][0]["Action"] == "s3:*"


# ------------------------------------------------------------------ routes


@pytest.mark.parametrize(
    ("fname", "code", "want_method", "want_path"),
    [
        ("a.py", '@app.route("/u", methods=["POST"])\ndef h():\n    pass\n', "POST", "/u"),
        ("a.py", '@router.get("/items")\nasync def h():\n    pass\n', "GET", "/items"),
        ("s.js", "app.delete('/u/:id', handler);\n", "DELETE", "/u/:id"),
        (
            "C.java",
            '@RestController\nclass C {\n  @PostMapping("/pay")\n  public void pay() {}\n}\n',
            "POST",
            "/pay",
        ),
        ("m.go", 'r.GET("/ping", h)\n', "GET", "/ping"),
    ],
)
def test_route_extraction(tmp_path: Path, fname: str, code: str, want_method: str, want_path: str) -> None:
    write(tmp_path, fname, code)
    routes = RouteSource().collect(SourceContext(root=tmp_path, exclude=[]))
    assert any(want_method in r.method and r.path == want_path for r in routes)


def test_routes_skip_excluded(tmp_path: Path) -> None:
    write(tmp_path, "tests/test_x.py", '@app.route("/x")\ndef h():\n    pass\n')
    routes = RouteSource().collect(SourceContext(root=tmp_path, exclude=["tests/"]))
    assert not routes
