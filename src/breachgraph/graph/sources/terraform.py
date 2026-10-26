"""Terraform (AWS) -> exposure, identities, effective permissions and data stores.

Azure and GCP resources from the same parse are handled in azure.py and gcp.py.

Static analysis of .tf files (no `terraform plan` needed). Values that are only known at apply
time (variables, computed ARNs) lower the confidence of the edges that depend on them instead of
being guessed silently.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
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
from breachgraph.graph.sources.azure import AzureTerraform
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.gcp import GcpTerraform
from breachgraph.graph.sources.hcl import decode_policy, literal, refs, truthy
from breachgraph.graph.sources.tfload import Res, module_views
from breachgraph.graph.sources.tfload import list_blocks as _list_blocks
from breachgraph.graph.sources.tfload import list_of as _list

ACCOUNT_ADMIN_ID = "aws:account-admin"
GITHUB_OIDC = "token.actions.githubusercontent.com"

# What "reading the data" means per data store type: (action patterns, value 0-10, label).
DATA_ACTIONS: dict[str, tuple[tuple[str, ...], int, str]] = {
    "aws_s3_bucket": (("s3:GetObject", "s3:ListBucket"), 7, "S3 bucket"),
    "aws_db_instance": (("rds-db:connect",), 9, "RDS database"),
    "aws_rds_cluster": (("rds-db:connect",), 9, "RDS cluster"),
    "aws_dynamodb_table": (
        ("dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query"),
        8,
        "DynamoDB table",
    ),
    "aws_secretsmanager_secret": (("secretsmanager:GetSecretValue",), 8, "Secrets Manager secret"),
    "aws_ssm_parameter": (("ssm:GetParameter", "ssm:GetParameters"), 6, "SSM parameter"),
    "aws_kms_key": (("kms:Decrypt",), 7, "KMS key"),
}
WRITE_ACTIONS = {
    "aws_s3_bucket": ("s3:PutObject", "s3:DeleteObject"),
    "aws_dynamodb_table": ("dynamodb:PutItem", "dynamodb:DeleteItem"),
}

# AWS-managed policies: the (action, resource) grants that matter for data access/escalation.
MANAGED_POLICIES: dict[str, list[tuple[str, str]]] = {
    "AdministratorAccess": [("*", "*")],
    "PowerUserAccess": [
        ("s3:*", "*"),
        ("dynamodb:*", "*"),
        ("secretsmanager:*", "*"),
        ("kms:*", "*"),
        ("ssm:*", "*"),
        ("lambda:*", "*"),
        ("ec2:*", "*"),
    ],
    "AmazonS3FullAccess": [("s3:*", "*")],
    "AmazonS3ReadOnlyAccess": [("s3:Get*", "*"), ("s3:List*", "*")],
    "AmazonDynamoDBFullAccess": [("dynamodb:*", "*")],
    "AmazonDynamoDBReadOnlyAccess": [
        ("dynamodb:Get*", "*"),
        ("dynamodb:Scan", "*"),
        ("dynamodb:Query", "*"),
    ],
    "SecretsManagerReadWrite": [("secretsmanager:*", "*")],
    "AmazonSSMFullAccess": [("ssm:*", "*")],
    "AmazonSSMReadOnlyAccess": [("ssm:Get*", "*")],
    "IAMFullAccess": [("iam:*", "*")],
    "ReadOnlyAccess": [
        ("s3:Get*", "*"),
        ("s3:List*", "*"),
        ("dynamodb:Get*", "*"),
        ("dynamodb:Scan", "*"),
        ("dynamodb:Query", "*"),
        ("ssm:Get*", "*"),
    ],
}

# Permission sets that let a principal grant itself more access (well-known IAM escalation
# primitives). Any one set present => the identity can become account administrator.
ESCALATION_SETS: list[tuple[set[str], str]] = [
    ({"iam:CreatePolicyVersion"}, "can rewrite a managed policy it is attached to"),
    ({"iam:SetDefaultPolicyVersion"}, "can switch a policy to a more permissive version"),
    (
        {"iam:AttachRolePolicy"},
        "can attach any managed policy (e.g. AdministratorAccess) to a role",
    ),
    ({"iam:AttachUserPolicy"}, "can attach any managed policy to a user"),
    ({"iam:PutRolePolicy"}, "can write an inline policy on a role"),
    ({"iam:PutUserPolicy"}, "can write an inline policy on a user"),
    ({"iam:CreateAccessKey"}, "can mint access keys for other users"),
    ({"iam:UpdateAssumeRolePolicy"}, "can let itself assume any role"),
    (
        {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
        "can run code as any passable role via Lambda",
    ),
    ({"iam:PassRole", "ec2:RunInstances"}, "can launch an instance with any passable role"),
    ({"iam:PassRole", "ecs:RunTask"}, "can run an ECS task with any passable role"),
    ({"iam:PassRole", "cloudformation:CreateStack"}, "can deploy a stack with any passable role"),
]


@dataclass
class Stmt:
    effect: str
    actions: list[str]
    resources: list[str]
    conditional: bool
    not_action: bool = False
    evidence: Evidence | None = None
    conditions: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (operator, key, values)
    principals: str = ""  # raw principal text, for trust policies


@dataclass
class _State:
    res: dict[str, Res] = field(default_factory=dict)  # "aws_iam_role.web" -> Res
    docs: dict[str, list[Stmt]] = field(default_factory=dict)  # "data.aws_iam_policy_document.x"
    role_stmts: dict[str, list[Stmt]] = field(default_factory=dict)  # role node id -> statements
    unresolved: list[str] = field(default_factory=list)


def _actions_match(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


class TerraformSource:
    name = "terraform"

    def collect(self, ctx: SourceContext, graph: Graph) -> None:
        skipped: list[str] = []
        for view in module_views(ctx):
            st = _State(res=view)
            for key, r in st.res.items():
                if r.rtype == "aws_iam_policy_document" and key.startswith("data."):
                    st.docs[key] = self._doc_statements(r)
            self._datastores(st, graph)
            self._roles(st, graph)
            self._permissions(st, graph)
            self._compute(st, graph)
            self._exposure(st, graph)
            skipped += st.unresolved
            AzureTerraform(st.res).collect(graph, skipped)
            GcpTerraform(st.res).collect(graph, skipped)
        ctx.skipped.extend(dict.fromkeys(skipped))  # views overlap: report each blind spot once

    # ------------------------------------------------------------------ helpers

    def _doc_statements(self, r: Res) -> list[Stmt]:
        out = []
        for s in _list_blocks(r.body.get("statement")):
            out.append(
                Stmt(
                    effect=str(s.get("effect", "Allow")),
                    actions=_list(s.get("actions") or s.get("not_actions")),
                    resources=_list(s.get("resources")) or ["*"],
                    conditional=bool(s.get("condition")),
                    not_action=bool(s.get("not_actions")),
                    evidence=r.ev,
                    conditions=[
                        (str(c.get("test", "")), str(c.get("variable", "")), _list(c.get("values")))
                        for c in _list_blocks(s.get("condition"))
                    ],
                    principals=str(s.get("principals", "")),
                )
            )
        return out

    def _policy(self, st: _State, value: Any, ev: Evidence) -> list[Stmt]:
        """Statements from an inline JSON/jsonencode policy or a policy_document reference."""
        for ref in refs(value):
            if ref.startswith("data.aws_iam_policy_document."):
                return st.docs.get(ref, [])
        doc = decode_policy(value)
        if doc is None:
            st.unresolved.append(f"{ev.label()}: IAM policy could not be evaluated statically")
            return []
        out = []
        for s in _list_blocks(doc.get("Statement")):
            out.append(
                Stmt(
                    effect=str(s.get("Effect", "Allow")),
                    actions=_list(s.get("Action") or s.get("NotAction")),
                    resources=_list(s.get("Resource")) or ["*"],
                    conditional=bool(s.get("Condition")),
                    not_action="NotAction" in s,
                    evidence=ev,
                    conditions=[
                        (str(op), str(key), _list(vals))
                        for op, body in (s.get("Condition") or {}).items()
                        if isinstance(body, dict)
                        for key, vals in body.items()
                    ],
                    principals=str(s.get("Principal", "")),
                )
            )
        return out

    def _node_for_ref(self, st: _State, value: Any, rtype: str) -> Res | None:
        for ref in refs(value):
            if ref.startswith(rtype + ".") and ref in st.res:
                return st.res[ref]
        return None

    # ------------------------------------------------------------------ data stores

    def _datastores(self, st: _State, graph: Graph) -> None:
        for key, r in st.res.items():
            if key.startswith("data.") or r.rtype not in DATA_ACTIONS:
                continue
            _actions, value, label = DATA_ACTIONS[r.rtype]
            ident = literal(r.body.get("bucket") or r.body.get("name") or r.body.get("identifier")) or r.name
            kind = (
                NodeKind.SECRET
                if r.rtype in ("aws_secretsmanager_secret", "aws_ssm_parameter", "aws_kms_key")
                else NodeKind.DATASTORE
            )
            r.node_id = f"aws:{r.rtype.removeprefix('aws_')}:{ident}"
            graph.add_node(
                Node(
                    id=r.node_id,
                    kind=kind,
                    name=f"{label} {ident}",
                    value=value,
                    attrs={
                        "tf": key,
                        "tf_range": [r.ev.path, r.ev.line, r.end_line],
                        "arn_name": ident,
                        "relational": r.rtype in ("aws_db_instance", "aws_rds_cluster"),
                    },
                    evidence=[r.ev],
                )
            )
        self._public_s3(st, graph)
        self._public_rds(st, graph)

    def _public_s3(self, st: _State, graph: Graph) -> None:
        pab: dict[str, dict[str, Any]] = {}
        for r in st.res.values():
            if r.rtype == "aws_s3_bucket_public_access_block":
                b = self._node_for_ref(st, r.body.get("bucket"), "aws_s3_bucket")
                if b:
                    pab[b.name] = r.body
        for r in st.res.values():
            if r.rtype not in ("aws_s3_bucket_policy", "aws_s3_bucket_acl"):
                continue
            b = self._node_for_ref(st, r.body.get("bucket"), "aws_s3_bucket")
            if b is None or b.node_id is None:
                continue
            block = pab.get(b.name, {})
            public = False
            why = ""
            if r.rtype == "aws_s3_bucket_acl" and str(r.body.get("acl", "")) in (
                "public-read",
                "public-read-write",
            ):
                public = not truthy(block.get("block_public_acls")) and not truthy(
                    block.get("ignore_public_acls")
                )
                why = f"bucket ACL is {r.body.get('acl')}"
            if r.rtype == "aws_s3_bucket_policy":
                for s in self._policy(st, r.body.get("policy"), r.ev):
                    principal_any = '"*"' in str(r.body.get("policy")) or 'Principal = "*"' in str(
                        r.body.get("policy")
                    )
                    if (
                        s.effect == "Allow"
                        and principal_any
                        and not s.conditional
                        and any(_actions_match(a, "s3:GetObject") for a in s.actions)
                    ):
                        public = not truthy(block.get("block_public_policy")) and not truthy(
                            block.get("restrict_public_buckets")
                        )
                        why = 'bucket policy allows s3:GetObject to Principal "*"'
            if public:
                graph.add_node(internet())
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=b.node_id,
                        kind=EdgeKind.CAN_ACCESS,
                        evidence=[r.ev],
                        confidence=Confidence.MEDIUM,
                        note=why + " (account-level Block Public Access, if enabled, would still stop this)",
                    )
                )

    def _public_rds(self, st: _State, graph: Graph) -> None:
        for r in st.res.values():
            if (
                r.rtype in ("aws_db_instance", "aws_rds_cluster_instance")
                and truthy(r.body.get("publicly_accessible"))
                and r.node_id
            ):
                ep_id = f"{r.node_id}:endpoint"
                graph.add_node(internet())
                graph.add_node(
                    Node(
                        id=ep_id,
                        kind=NodeKind.ENTRYPOINT,
                        name=f"Public endpoint of {r.name}",
                        attrs={"tf_range": [r.ev.path, r.ev.line, r.end_line]},
                        evidence=[r.ev],
                    )
                )
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=ep_id,
                        kind=EdgeKind.EXPOSES,
                        evidence=[r.ev],
                        confidence=Confidence.MEDIUM,
                        note="publicly_accessible = true (reachable if its security group allows it)",
                    )
                )
                pw = r.body.get("password")
                if literal(pw):
                    graph.nodes[ep_id].weaknesses.append(
                        Weakness(
                            cls=WeaknessClass.CREDENTIAL_EXPOSURE,
                            title="database master password is hardcoded in Terraform",
                            evidence=r.ev,
                        )
                    )
                graph.add_edge(
                    Edge(
                        src=ep_id,
                        dst=r.node_id,
                        kind=EdgeKind.CAN_ACCESS,
                        evidence=[r.ev],
                        requires=[WeaknessClass.CREDENTIAL_EXPOSURE],
                        note="requires valid database credentials",
                    )
                )

    # ------------------------------------------------------------------ identities

    def _roles(self, st: _State, graph: Graph) -> None:
        for key, r in st.res.items():
            if r.rtype != "aws_iam_role" or key.startswith("data."):
                continue
            name = literal(r.body.get("name")) or r.name
            r.node_id = f"aws:iam_role:{name}"
            node = graph.add_node(
                Node(
                    id=r.node_id,
                    kind=NodeKind.IDENTITY,
                    name=f"IAM role {name}",
                    attrs={"platform": "aws", "tf": key},
                    evidence=[r.ev],
                )
            )
            trust = self._policy(st, r.body.get("assume_role_policy"), r.ev)
            raw_trust = str(r.body.get("assume_role_policy"))
            for s in trust:
                if s.effect != "Allow":
                    continue
                # IRSA: a Kubernetes service account may assume this role via the cluster's OIDC.
                for ns, sa in re.findall(r"system:serviceaccount:([\w.-]+):([\w.*-]+)", raw_trust):
                    said = f"k8s:serviceaccount:{ns}/{sa}"
                    graph.add_node(
                        Node(
                            id=said,
                            kind=NodeKind.IDENTITY,
                            name=f"ServiceAccount {ns}/{sa}",
                            evidence=[r.ev],
                        )
                    )
                    graph.add_edge(
                        Edge(
                            src=said,
                            dst=node.id,
                            kind=EdgeKind.USES_IDENTITY,
                            evidence=[r.ev],
                            note="IRSA trust policy",
                        )
                    )
                if GITHUB_OIDC in s.principals:
                    self._github_trust(graph, node, s, r)
                if re.search(r'AWS\W+(=|:)\s*\W*"\*"', raw_trust) and not s.conditional:
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=node.id,
                            kind=EdgeKind.USES_IDENTITY,
                            evidence=[r.ev],
                            note=(
                                'trust policy allows Principal {"AWS": "*"} with no '
                                "condition: any AWS account can assume it"
                            ),
                        )
                    )
            stmts: list[Stmt] = []
            for inline in _list_blocks(r.body.get("inline_policy")):
                stmts += self._policy(st, inline.get("policy"), r.ev)
            for arn in _list(r.body.get("managed_policy_arns")):
                stmts += _managed(arn, r.ev)
            st.role_stmts[node.id] = stmts

    def _github_trust(self, graph: Graph, node: Node, s: Stmt, r: Res) -> None:
        """A role GitHub Actions can assume through OIDC. Record which workflows may (the `sub`
        patterns); a trust with no repository in `sub` lets any GitHub repository assume it."""
        subs = [v for _op, key, vals in s.conditions if key.endswith(":sub") for v in vals]
        known = node.attrs.get("github_oidc_subs")
        node.attrs["github_oidc_subs"] = [*(known if isinstance(known, list) else []), *(subs or ["*"])]
        open_to_all = not subs or any(re.match(r"^(\*|repo:\*)", v) for v in subs)
        if open_to_all:
            graph.add_node(internet())
            graph.add_edge(
                Edge(
                    src=INTERNET_ID,
                    dst=node.id,
                    kind=EdgeKind.USES_IDENTITY,
                    evidence=[r.ev],
                    note="trusts GitHub Actions OIDC without restricting the repository "
                    f"({'no sub condition' if not subs else 'sub ' + subs[0]}): a workflow in any "
                    "GitHub repository can assume it",
                )
            )

    def _permissions(self, st: _State, graph: Graph) -> None:
        policies: dict[str, list[Stmt]] = {}
        for key, r in st.res.items():
            if r.rtype == "aws_iam_policy" and not key.startswith("data."):
                policies[key] = self._policy(st, r.body.get("policy"), r.ev)
        for r in st.res.values():
            role = self._node_for_ref(st, r.body.get("role"), "aws_iam_role")
            if role is None or role.node_id is None:
                if r.rtype in ("aws_iam_role_policy", "aws_iam_role_policy_attachment") and literal(
                    r.body.get("role")
                ):
                    rid = f"aws:iam_role:{r.body['role']}"
                    if rid not in graph.nodes:
                        continue
                    target = rid
                else:
                    continue
            else:
                target = role.node_id
            if r.rtype == "aws_iam_role_policy":
                st.role_stmts.setdefault(target, []).extend(self._policy(st, r.body.get("policy"), r.ev))
            elif r.rtype == "aws_iam_role_policy_attachment":
                arn = r.body.get("policy_arn")
                pol = next((policies[x] for x in refs(arn) if x in policies), None)
                st.role_stmts.setdefault(target, []).extend(
                    pol if pol is not None else _managed(str(arn), r.ev)
                )

        for role_id, stmts in st.role_stmts.items():
            self._grant_edges(st, graph, role_id, stmts)

    def _allowed(self, stmts: list[Stmt], action: str, resource_ok: Any) -> tuple[bool, bool, Stmt | None]:
        """(allowed, conditional, granting statement). Explicit Deny wins."""
        grant: Stmt | None = None
        for s in stmts:
            hit = any(_actions_match(a, action) for a in s.actions)
            if s.not_action:
                hit = not hit
            if hit and resource_ok(s.resources):
                if s.effect == "Deny" and not s.conditional:
                    return False, False, None
                if s.effect == "Allow" and grant is None:
                    grant = s
        return grant is not None, bool(grant and grant.conditional), grant

    def _grant_edges(self, st: _State, graph: Graph, role_id: str, stmts: list[Stmt]) -> None:
        any_resource = lambda res: any(x == "*" for x in res)  # noqa: E731
        # Account takeover: full admin or an escalation primitive.
        full, fcond, fgrant = self._allowed(stmts, "anyservice:AnyAction", any_resource)
        reason = None
        if full:
            reason, cond, grant = (
                'has full administrator permissions (Action "*" on "*")',
                fcond,
                fgrant,
            )
        else:
            for needed, why in ESCALATION_SETS:
                checks = [self._allowed(stmts, a, any_resource) for a in needed]
                if all(c[0] for c in checks):
                    reason, cond, grant = why, any(c[1] for c in checks), checks[0][2]
                    break
        if reason:
            graph.add_node(
                Node(
                    id=ACCOUNT_ADMIN_ID,
                    kind=NodeKind.IDENTITY,
                    name="AWS account administrator",
                    value=10,
                )
            )
            graph.add_edge(
                Edge(
                    src=role_id,
                    dst=ACCOUNT_ADMIN_ID,
                    kind=EdgeKind.USES_IDENTITY,
                    evidence=[grant.evidence] if grant and grant.evidence else [],
                    confidence=Confidence.MEDIUM if cond else Confidence.HIGH,
                    note=f"privilege escalation: {reason}",
                )
            )
            for r in st.res.values():
                if r.node_id and r.rtype in DATA_ACTIONS:
                    graph.add_edge(
                        Edge(
                            src=ACCOUNT_ADMIN_ID,
                            dst=r.node_id,
                            kind=EdgeKind.CAN_ACCESS,
                            note="administrator",
                        )
                    )

        # Data access per store.
        for r in st.res.values():
            if not r.node_id or r.rtype not in DATA_ACTIONS:
                continue
            ident = str(graph.nodes[r.node_id].attrs.get("arn_name"))
            tf_ref = next(k for k, v in st.res.items() if v is r)

            def res_ok(resources: list[str], ident: str = ident, tf_ref: str = tf_ref) -> bool:
                for x in resources:
                    if (
                        x == "*"
                        or tf_ref in x
                        or (ident and re.search(rf"[:/]{re.escape(ident)}(/|\*|$)", x))
                    ):
                        return True
                    if x.startswith("arn:") and fnmatch.fnmatchcase(f"arn:aws:s3:::{ident}", x.split("/")[0]):
                        return True
                return False

            actions, _value, _label = DATA_ACTIONS[r.rtype]
            for action in actions:
                ok, cond, grant = self._allowed(stmts, action, res_ok)
                if ok:
                    writes = [a for a in WRITE_ACTIONS.get(r.rtype, ()) if self._allowed(stmts, a, res_ok)[0]]
                    graph.add_edge(
                        Edge(
                            src=role_id,
                            dst=r.node_id,
                            kind=EdgeKind.CAN_ACCESS,
                            evidence=[grant.evidence] if grant and grant.evidence else [],
                            confidence=Confidence.MEDIUM if cond else Confidence.HIGH,
                            note=f"{action}"
                            + (f" + {', '.join(writes)}" if writes else "")
                            + (" (conditional)" if cond else ""),
                        )
                    )
                    break

    # ------------------------------------------------------------------ compute

    def _compute(self, st: _State, graph: Graph) -> None:
        profiles = {
            k: self._node_for_ref(st, r.body.get("role"), "aws_iam_role")
            for k, r in st.res.items()
            if r.rtype == "aws_iam_instance_profile"
        }
        for key, r in st.res.items():
            if key.startswith("data."):
                continue
            if r.rtype == "aws_instance":
                r.node_id = f"aws:ec2:{r.name}"
                meta = (_list_blocks(r.body.get("metadata_options")) or [{}])[0]
                imdsv2 = str(meta.get("http_tokens", "optional")) == "required"
                node = graph.add_node(
                    Node(
                        id=r.node_id,
                        kind=NodeKind.WORKLOAD,
                        name=f"EC2 instance {r.name}",
                        attrs={
                            "platform": "ec2",
                            "imdsv2": imdsv2,
                            "tf_range": [r.ev.path, r.ev.line, r.end_line],
                        },
                        evidence=[r.ev],
                    )
                )
                node.weaknesses.append(
                    Weakness(
                        cls=WeaknessClass.METADATA_REACHABLE,
                        evidence=r.ev,
                        title="instance metadata (IMDS) is reachable"
                        + ("" if imdsv2 else " and IMDSv1 is allowed (http_tokens != required)"),
                    )
                )
                for ref in refs(r.body.get("iam_instance_profile")):
                    role = profiles.get(ref)
                    if role and role.node_id:
                        graph.add_edge(
                            Edge(
                                src=node.id,
                                dst=role.node_id,
                                kind=EdgeKind.USES_IDENTITY,
                                requires=CONTROL,
                                evidence=[r.ev],
                                note="using the instance role requires running code on the instance",
                            )
                        )
            elif r.rtype == "aws_eks_node_group":
                role = self._node_for_ref(st, r.body.get("node_role_arn"), "aws_iam_role")
                if role and role.node_id:
                    host = "k8s:host:nodes"
                    graph.add_node(
                        Node(
                            id=host,
                            kind=NodeKind.HOST,
                            name="Kubernetes worker nodes",
                            evidence=[r.ev],
                        )
                    )
                    graph.add_edge(
                        Edge(
                            src=host,
                            dst=role.node_id,
                            kind=EdgeKind.USES_IDENTITY,
                            evidence=[r.ev],
                            note="EKS node role via instance metadata",
                        )
                    )
                    graph.nodes[role.node_id].attrs["eks_node_role"] = True
            elif r.rtype == "aws_ecs_task_definition":
                role = self._node_for_ref(st, r.body.get("task_role_arn"), "aws_iam_role")
                r.node_id = f"aws:ecs_task:{literal(r.body.get('family')) or r.name}"
                node = graph.add_node(
                    Node(
                        id=r.node_id,
                        kind=NodeKind.WORKLOAD,
                        name=f"ECS task {r.name}",
                        attrs={
                            "platform": "ecs",
                            "tf_range": [r.ev.path, r.ev.line, r.end_line],
                            "images": re.findall(
                                r'image\W+(?:=|:)\s*"([^"$]+)"',
                                str(r.body.get("container_definitions")),
                            ),
                        },
                        evidence=[r.ev],
                    )
                )
                node.weaknesses.append(
                    Weakness(
                        cls=WeaknessClass.METADATA_REACHABLE,
                        evidence=r.ev,
                        title="ECS task credentials endpoint (169.254.170.2) is reachable from the container",
                    )
                )
                if role and role.node_id:
                    graph.add_edge(
                        Edge(
                            src=node.id,
                            dst=role.node_id,
                            kind=EdgeKind.USES_IDENTITY,
                            requires=CONTROL,
                            evidence=[r.ev],
                            note="using the task role requires running code in the task",
                        )
                    )
            elif r.rtype == "aws_lambda_function":
                role = self._node_for_ref(st, r.body.get("role"), "aws_iam_role")
                r.node_id = f"aws:lambda:{literal(r.body.get('function_name')) or r.name}"
                graph.add_node(
                    Node(
                        id=r.node_id,
                        kind=NodeKind.WORKLOAD,
                        name=f"Lambda {r.name}",
                        attrs={
                            "platform": "lambda",
                            "handler": r.body.get("handler"),
                            "tf_range": [r.ev.path, r.ev.line, r.end_line],
                        },
                        evidence=[r.ev],
                    )
                )
                if role and role.node_id:
                    graph.add_edge(
                        Edge(
                            src=r.node_id,
                            dst=role.node_id,
                            kind=EdgeKind.USES_IDENTITY,
                            requires=CONTROL,
                            evidence=[r.ev],
                            note="using the function role requires code execution in the function",
                        )
                    )
        for r in st.res.values():  # ECS services point at task definitions
            if r.rtype == "aws_ecs_service":
                td = self._node_for_ref(st, r.body.get("task_definition"), "aws_ecs_task_definition")
                if td and td.node_id:
                    r.node_id = td.node_id

    # ------------------------------------------------------------------ exposure

    def _exposure(self, st: _State, graph: Graph) -> None:
        open_sgs: dict[str, list[str]] = {}
        for key, r in st.res.items():
            if r.rtype == "aws_security_group":
                ports = [
                    f"{i.get('from_port')}-{i.get('to_port')}"
                    for i in _list_blocks(r.body.get("ingress"))
                    if "0.0.0.0/0" in _list(i.get("cidr_blocks"))
                    or "::/0" in _list(i.get("ipv6_cidr_blocks"))
                ]
                if ports:
                    open_sgs[key] = ports
            elif r.rtype in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
                cidrs = _list(r.body.get("cidr_blocks")) + _list(r.body.get("cidr_ipv4"))
                if str(r.body.get("type", "ingress")) == "ingress" and "0.0.0.0/0" in cidrs:
                    for sg in refs(r.body.get("security_group_id")):
                        open_sgs.setdefault(sg, []).append(
                            f"{r.body.get('from_port')}-{r.body.get('to_port')}"
                        )

        # Internet-facing load balancers -> listener -> target group -> workload
        tg_to_workload: dict[str, list[str]] = {}
        for r in st.res.values():
            if r.rtype == "aws_ecs_service" and r.node_id:
                for lb in _list_blocks(r.body.get("load_balancer")):
                    for tg in refs(lb.get("target_group_arn")):
                        tg_to_workload.setdefault(tg, []).append(r.node_id)
            if r.rtype == "aws_lb_target_group_attachment":
                inst = self._node_for_ref(st, r.body.get("target_id"), "aws_instance")
                for tg in refs(r.body.get("target_group_arn")):
                    if inst and inst.node_id:
                        tg_to_workload.setdefault(tg, []).append(inst.node_id)
        for key, r in st.res.items():
            if r.rtype in ("aws_lb", "aws_alb") and not truthy(r.body.get("internal")):
                ep = f"aws:lb:{r.name}"
                graph.add_node(internet())
                graph.add_node(
                    Node(
                        id=ep,
                        kind=NodeKind.ENTRYPOINT,
                        name=f"Load balancer {r.name}",
                        evidence=[r.ev],
                    )
                )
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=ep,
                        kind=EdgeKind.EXPOSES,
                        evidence=[r.ev],
                        note="internet-facing (internal = false)",
                    )
                )
                for lr in st.res.values():
                    if lr.rtype in ("aws_lb_listener", "aws_alb_listener") and key in refs(
                        lr.body.get("load_balancer_arn")
                    ):
                        for tg in refs(lr.body.get("default_action")):
                            for w in tg_to_workload.get(tg, []):
                                graph.add_edge(Edge(src=ep, dst=w, kind=EdgeKind.EXPOSES, evidence=[lr.ev]))

        # EC2 instances with a public IP and an open security group
        for r in st.res.values():
            if r.rtype == "aws_instance" and r.node_id:
                sgs = [
                    s
                    for s in refs(r.body.get("vpc_security_group_ids")) + refs(r.body.get("security_groups"))
                    if s in open_sgs
                ]
                public_ip = truthy(r.body.get("associate_public_ip_address"))
                if sgs:
                    ports = [p for s in sgs for p in open_sgs[s]]
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=r.node_id,
                            kind=EdgeKind.EXPOSES,
                            evidence=[r.ev],
                            confidence=Confidence.HIGH if public_ip else Confidence.MEDIUM,
                            note=f"security group open to 0.0.0.0/0 on {', '.join(ports)}"
                            + ("" if public_ip else " (public IP depends on the subnet)"),
                        )
                    )

        # Lambda function URLs / API Gateway without authorization
        for r in st.res.values():
            if r.rtype == "aws_lambda_function_url" and str(r.body.get("authorization_type", "")) == "NONE":
                fn = self._node_for_ref(st, r.body.get("function_name"), "aws_lambda_function")
                if fn and fn.node_id:
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=fn.node_id,
                            kind=EdgeKind.EXPOSES,
                            evidence=[r.ev],
                            note="Lambda function URL with authorization_type NONE",
                        )
                    )
            if r.rtype == "aws_apigatewayv2_integration":
                fn = self._node_for_ref(st, r.body.get("integration_uri"), "aws_lambda_function")
                if fn and fn.node_id:
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=fn.node_id,
                            kind=EdgeKind.EXPOSES,
                            evidence=[r.ev],
                            confidence=Confidence.MEDIUM,
                            note="API Gateway integration (check route authorizers)",
                        )
                    )


def _managed(arn: str, ev: Evidence) -> list[Stmt]:
    name = arn.rsplit("/", 1)[-1].strip('"')
    grants = MANAGED_POLICIES.get(name)
    if grants is None:
        return []
    ev2 = Evidence(path=ev.path, line=ev.line, detail=f"AWS managed policy {name}", source="terraform")
    return [Stmt("Allow", [a], [res], False, evidence=ev2) for a, res in grants]
