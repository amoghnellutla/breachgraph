"""Terraform (google) -> GCP exposure, service accounts, effective IAM bindings, data stores.

Same model as the AWS source: a service account reaches a data store only when an IAM binding whose
resource covers that store grants a permission that yields the data, or lets it rewrite the store's
IAM policy. Bindings that let it mint tokens or keys for another service account become identity
edges, so impersonation chains are followed. Attribute names follow the google provider 5.x/6.x
docs (checked 2026-10).
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Graph,
    Node,
    NodeKind,
    Weakness,
    WeaknessClass,
    internet,
)
from breachgraph.graph.sources.hcl import literal, refs, truthy
from breachgraph.graph.sources.tfload import Res, attr_refs, code_paths, first_block, list_blocks, list_of

PROJECT_OWNER_ID = "gcp:project-owner"
K8S_NODES_ID = "k8s:host:nodes"
METADATA_HEADER = "the required Metadata-Flavor: Google header"

# type -> (node kind, value 0-10, label, relational, name attribute)
DATASTORES: dict[str, tuple[NodeKind, int, str, bool, str]] = {
    "google_storage_bucket": (NodeKind.DATASTORE, 7, "GCS bucket", False, "name"),
    "google_sql_database_instance": (NodeKind.DATASTORE, 9, "Cloud SQL instance", True, "name"),
    "google_bigquery_dataset": (NodeKind.DATASTORE, 8, "BigQuery dataset", False, "dataset_id"),
    "google_secret_manager_secret": (NodeKind.SECRET, 8, "Secret Manager secret", False, "secret_id"),
    "google_kms_crypto_key": (NodeKind.SECRET, 7, "KMS key", False, "name"),
}
# Permissions that yield a store's data, or let the holder grant itself access to it.
READ_PATHS: dict[str, list[tuple[str, str]]] = {
    "google_storage_bucket": [
        ("storage.objects.get", "read objects"),
        ("storage.buckets.setIamPolicy", "grant itself access to the bucket"),
    ],
    "google_sql_database_instance": [("cloudsql.users.update", "reset a database user's password")],
    "google_bigquery_dataset": [
        ("bigquery.tables.getData", "read table data"),
        ("bigquery.datasets.setIamPolicy", "grant itself access to the dataset"),
    ],
    "google_secret_manager_secret": [
        ("secretmanager.versions.access", "read secret versions"),
        ("secretmanager.secrets.setIamPolicy", "grant itself access to the secret"),
    ],
    "google_kms_crypto_key": [
        ("cloudkms.cryptoKeyVersions.useToDecrypt", "decrypt with the key"),
        ("cloudkms.cryptoKeys.setIamPolicy", "grant itself decrypt on the key"),
    ],
}
IMPERSONATE = [
    ("iam.serviceAccounts.getAccessToken", "mint access tokens for it"),
    ("iam.serviceAccountKeys.create", "create keys for it"),
    ("iam.serviceAccounts.setIamPolicy", "grant itself token creation on it"),
]
PROJECT_ESCALATION = "resourcemanager.projects.setIamPolicy"

# Predefined roles that matter for data access, impersonation or escalation:
# (permission patterns, excluded patterns).
ROLES: dict[str, tuple[list[str], list[str]]] = {
    "roles/owner": (["*"], []),
    "roles/editor": (["*"], ["*.setIamPolicy", "*.getIamPolicy", "iam.serviceAccounts.getAccessToken"]),
    "roles/viewer": ([], []),
    "roles/browser": ([], []),
    "roles/storage.admin": (["storage.*"], []),
    "roles/storage.objectAdmin": (["storage.objects.*"], []),
    "roles/storage.objectUser": (["storage.objects.*"], ["storage.objects.setIamPolicy"]),
    "roles/storage.objectViewer": (["storage.objects.get", "storage.objects.list"], []),
    "roles/storage.objectCreator": (["storage.objects.create"], []),
    "roles/storage.legacyObjectReader": (["storage.objects.get"], []),
    "roles/storage.legacyBucketReader": (["storage.buckets.get", "storage.objects.list"], []),
    "roles/storage.legacyBucketOwner": (["storage.buckets.*", "storage.objects.list"], []),
    "roles/secretmanager.admin": (["secretmanager.*"], []),
    "roles/secretmanager.secretAccessor": (["secretmanager.versions.access"], []),
    "roles/secretmanager.viewer": (["secretmanager.secrets.get", "secretmanager.secrets.list"], []),
    "roles/bigquery.admin": (["bigquery.*"], []),
    "roles/bigquery.dataOwner": (["bigquery.tables.*", "bigquery.datasets.*"], []),
    "roles/bigquery.dataEditor": (["bigquery.tables.*"], ["bigquery.tables.setIamPolicy"]),
    "roles/bigquery.dataViewer": (
        ["bigquery.tables.getData", "bigquery.tables.get", "bigquery.tables.list"],
        [],
    ),
    "roles/cloudsql.admin": (["cloudsql.*"], []),
    "roles/cloudsql.editor": (["cloudsql.instances.*", "cloudsql.databases.*"], []),
    "roles/cloudsql.client": (["cloudsql.instances.connect", "cloudsql.instances.get"], []),
    "roles/cloudkms.admin": (["cloudkms.*"], ["cloudkms.cryptoKeyVersions.useTo*"]),
    "roles/cloudkms.cryptoKeyDecrypter": (["cloudkms.cryptoKeyVersions.useToDecrypt"], []),
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": (["cloudkms.cryptoKeyVersions.useTo*"], []),
    "roles/iam.serviceAccountTokenCreator": (
        [
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.sign*",
            "iam.serviceAccounts.getOpenIdToken",
        ],
        [],
    ),
    "roles/iam.serviceAccountKeyAdmin": (["iam.serviceAccountKeys.*"], []),
    "roles/iam.serviceAccountAdmin": (["iam.serviceAccounts.*"], ["iam.serviceAccounts.getAccessToken"]),
    "roles/iam.serviceAccountUser": (["iam.serviceAccounts.actAs"], []),
    "roles/iam.workloadIdentityUser": (["iam.serviceAccounts.getAccessToken"], []),
    "roles/resourcemanager.projectIamAdmin": (["resourcemanager.projects.*IamPolicy"], []),
    "roles/iam.securityAdmin": (["*.setIamPolicy", "*.getIamPolicy"], []),
    "roles/run.invoker": (["run.routes.invoke"], []),
    "roles/cloudfunctions.invoker": (["cloudfunctions.functions.invoke"], []),
}
# IAM resource type -> (scope kind, attribute naming the resource)
IAM_RESOURCES: dict[str, tuple[str, str]] = {
    "google_project_iam": ("project", "project"),
    "google_folder_iam": ("project", "folder"),
    "google_organization_iam": ("project", "org_id"),
    "google_storage_bucket_iam": ("google_storage_bucket", "bucket"),
    "google_secret_manager_secret_iam": ("google_secret_manager_secret", "secret_id"),
    "google_bigquery_dataset_iam": ("google_bigquery_dataset", "dataset_id"),
    "google_kms_crypto_key_iam": ("google_kms_crypto_key", "crypto_key_id"),
    "google_service_account_iam": ("service_account", "service_account_id"),
    "google_cloud_run_service_iam": ("invoke", "service"),
    "google_cloud_run_v2_service_iam": ("invoke", "name"),
    "google_cloudfunctions_function_iam": ("invoke", "cloud_function"),
    "google_cloudfunctions2_function_iam": ("invoke", "cloud_function"),
}
_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}
_WI_MEMBER_RE = re.compile(r"serviceAccount:[^\[\s\"]*\.svc\.id\.goog\[([\w.-]+)/([\w.-]+)\]")


def _allows(perms: list[str], excluded: list[str], perm: str) -> bool:
    p = perm.lower()
    hit = any(fnmatch.fnmatchcase(p, x.lower()) for x in perms)
    return hit and not any(fnmatch.fnmatchcase(p, x.lower()) for x in excluded)


def sa_id(email_or_id: str) -> str:
    """Node id for a service account, from its account_id or email."""
    # Accepts `name`, `name@project.iam.gserviceaccount.com` and `projects/P/serviceAccounts/EMAIL`.
    name = email_or_id.rsplit("/", 1)[-1].removeprefix("serviceAccount:")
    return f"gcp:service_account:{name.split('@', 1)[0]}"


class GcpTerraform:
    def __init__(self, res: dict[str, Res]) -> None:
        self.all_res = res  # every block, for provider-neutral ones such as data.archive_file
        self.res = {k: v for k, v in res.items() if v.rtype.startswith("google_")}
        self.stores: dict[str, Res] = {}
        self.sas: dict[str, Res] = {}  # node id -> google_service_account
        self.skipped: list[str] = []

    def collect(self, graph: Graph, skipped: list[str]) -> None:
        if not self.res:
            return
        self.skipped = skipped
        self._datastores(graph)
        self._service_accounts(graph)
        self._compute(graph)
        self._gke(graph)
        self._bindings(graph)
        self._public_acls(graph)
        self._public_sql(graph)
        self._vm_exposure(graph)

    # ------------------------------------------------------------------ helpers

    def _first(self, value: Any, *types: str) -> Res | None:
        for ref in refs(value):
            r = self.res.get(ref)
            if r and (not types or r.rtype in types):
                return r
        return None

    def _name(self, r: Res, attr: str = "name") -> str:
        return literal(r.body.get(attr)) or r.name

    def _sa(self, value: Any, graph: Graph) -> str | None:
        """Service account node for an email/member expression (reference or literal)."""
        for ref, _tail in attr_refs(value):
            r = self.res.get(ref)
            if r and r.rtype == "google_service_account" and r.node_id:
                return r.node_id
        text = literal(value)
        if text and text.removeprefix("serviceAccount:").endswith(".gserviceaccount.com"):
            email = text.removeprefix("serviceAccount:")
            nid = sa_id(email)
            if nid not in graph.nodes:
                graph.add_node(
                    Node(
                        id=nid,
                        kind=NodeKind.IDENTITY,
                        name=f"Service account {email}",
                        attrs={"platform": "gcp"},
                    )
                )
            return nid
        return None

    # ------------------------------------------------------------------ data stores and identities

    def _datastores(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if key.startswith("data.") or r.rtype not in DATASTORES:
                continue
            kind, value, label, relational, attr = DATASTORES[r.rtype]
            name = self._name(r, attr)
            r.node_id = f"gcp:{r.rtype.removeprefix('google_')}:{name}"
            graph.add_node(
                Node(
                    id=r.node_id,
                    kind=kind,
                    name=f"{label} {name}",
                    value=value,
                    attrs={
                        "platform": "gcp",
                        "tf": key,
                        "tf_range": r.tf_range,
                        "relational": relational,
                        "queryable": relational or r.rtype == "google_bigquery_dataset",
                    },
                    evidence=[r.ev],
                )
            )
            self.stores[r.node_id] = r

    def _service_accounts(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if r.rtype == "google_service_account" and not key.startswith("data."):
                account = self._name(r, "account_id")
                r.node_id = sa_id(account)
                graph.add_node(
                    Node(
                        id=r.node_id,
                        kind=NodeKind.IDENTITY,
                        name=f"Service account {account}",
                        attrs={"platform": "gcp", "tf": key},
                        evidence=[r.ev],
                    )
                )
                self.sas[r.node_id] = r

    # ------------------------------------------------------------------ compute

    def _workload(
        self,
        graph: Graph,
        r: Res,
        label: str,
        platform: str,
        images: list[str],
        sa_value: Any,
        scopes: Any = None,
    ) -> None:
        name = self._name(r)
        r.node_id = f"gcp:{r.rtype.removeprefix('google_')}:{name}"
        graph.add_node(
            Node(
                id=r.node_id,
                kind=NodeKind.WORKLOAD,
                name=f"{label} {name}",
                attrs={
                    "platform": platform,
                    "tf_range": r.tf_range,
                    "images": images,
                    "code_paths": code_paths(self.all_res, r),
                    "metadata_header": METADATA_HEADER,
                },
                evidence=[r.ev],
                weaknesses=[
                    Weakness(
                        cls=WeaknessClass.METADATA_REACHABLE,
                        evidence=r.ev,
                        title="GCP metadata server (metadata.google.internal) issues tokens for the "
                        "workload's service account",
                    )
                ],
            )
        )
        sa = self._sa(sa_value, graph) if sa_value else None
        if sa is None:
            return
        limited = scopes is not None and not any("cloud-platform" in s for s in list_of(scopes))
        graph.add_edge(
            Edge(
                src=r.node_id,
                dst=sa,
                kind=EdgeKind.USES_IDENTITY,
                requires=CONTROL,
                evidence=[r.ev],
                confidence=Confidence.MEDIUM if limited else Confidence.HIGH,
                note="using the service account requires running code in the workload"
                + (" (its access scopes may limit the token)" if limited else ""),
            )
        )

    def _compute(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if key.startswith("data."):
                continue
            b = r.body
            if r.rtype == "google_compute_instance":
                sa = first_block(b.get("service_account"))
                self._workload(graph, r, "Compute instance", "gce", [], sa.get("email"), sa.get("scopes", []))
            elif r.rtype == "google_cloud_run_v2_service":
                t = first_block(b.get("template"))
                images = [
                    str(c["image"]) for c in list_blocks(t.get("containers")) if literal(c.get("image"))
                ]
                self._workload(graph, r, "Cloud Run service", "cloud-run", images, t.get("service_account"))
            elif r.rtype == "google_cloud_run_service":
                spec = first_block(first_block(b.get("template")).get("spec"))
                images = [
                    str(c["image"]) for c in list_blocks(spec.get("containers")) if literal(c.get("image"))
                ]
                self._workload(
                    graph, r, "Cloud Run service", "cloud-run", images, spec.get("service_account_name")
                )
            elif r.rtype == "google_cloudfunctions_function":
                self._workload(
                    graph, r, "Cloud Function", "cloud-functions", [], b.get("service_account_email")
                )
            elif r.rtype == "google_cloudfunctions2_function":
                svc = first_block(b.get("service_config"))
                self._workload(
                    graph, r, "Cloud Function", "cloud-functions", [], svc.get("service_account_email")
                )

    def _gke(self, graph: Graph) -> None:
        for r in self.res.values():
            if r.rtype not in ("google_container_cluster", "google_container_node_pool"):
                continue
            sa_value = first_block(r.body.get("node_config")).get("service_account")
            if not sa_value:
                if r.rtype == "google_container_node_pool" or not truthy(
                    r.body.get("remove_default_node_pool")
                ):
                    self.skipped.append(
                        f"{r.ev.label()}: GKE nodes use the Compute Engine default service account, whose "
                        "roles are not in Terraform"
                    )
                continue
            sa = self._sa(sa_value, graph)
            if sa is None:
                continue
            graph.add_node(
                Node(id=K8S_NODES_ID, kind=NodeKind.HOST, name="Kubernetes worker nodes", evidence=[r.ev])
            )
            graph.add_edge(
                Edge(
                    src=K8S_NODES_ID,
                    dst=sa,
                    kind=EdgeKind.USES_IDENTITY,
                    evidence=[r.ev],
                    note="GKE node service account via the node's metadata server",
                )
            )

    # ------------------------------------------------------------------ IAM

    def _role(self, r: Res, role_value: Any) -> tuple[str, list[str], list[str]] | None:
        name = literal(role_value)
        if name in ROLES:
            return name, *ROLES[name]
        custom = self._first(
            role_value, "google_project_iam_custom_role", "google_organization_iam_custom_role"
        )
        if custom:
            return self._name(custom, "role_id"), list_of(custom.body.get("permissions")), []
        self.skipped.append(
            f"{r.ev.label()}: GCP role '{name or role_value}' is not modeled, binding ignored"
        )
        return None

    def _bindings(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if key.startswith("data."):
                continue
            base = re.sub(r"_(member|binding|policy)$", "", r.rtype)
            if base not in IAM_RESOURCES or base == r.rtype:
                continue
            scope_kind, attr = IAM_RESOURCES[base]
            conditional = bool(r.body.get("condition"))
            if r.rtype.endswith("_policy"):
                doc = self._first(r.body.get("policy_data"), "google_iam_policy")
                if doc is None:
                    self.skipped.append(f"{r.ev.label()}: IAM policy_data could not be resolved statically")
                    continue
                entries = [
                    (b.get("role"), list_of(b.get("members")), bool(b.get("condition")))
                    for b in list_blocks(doc.body.get("binding"))
                ]
            else:
                members = list_of(r.body.get("members")) or list_of(r.body.get("member"))
                entries = [(r.body.get("role"), members, conditional)]
            for role_value, members, cond in entries:
                self._binding(graph, r, scope_kind, r.body.get(attr), role_value, members, cond)

    def _binding(
        self,
        graph: Graph,
        r: Res,
        scope_kind: str,
        target: Any,
        role_value: Any,
        members: list[str],
        cond: bool,
    ) -> None:
        role = self._role(r, role_value)
        if role is None:
            return
        role_name, perms, excluded = role
        conf = Confidence.MEDIUM if cond else Confidence.HIGH
        public = [m for m in members if m.lower() in _PUBLIC_MEMBERS]
        if scope_kind == "invoke":
            fn = self._first(target)
            if (
                public
                and fn
                and fn.node_id
                and role_name in ("roles/run.invoker", "roles/cloudfunctions.invoker")
            ):
                self._expose(graph, fn, r, f"{role_name} granted to {public[0]}")
            return
        if scope_kind == "service_account":
            sa = self._sa(target, graph)
            for m in members:
                wi = _WI_MEMBER_RE.search(m)
                if wi and sa and role_name == "roles/iam.workloadIdentityUser":
                    self._workload_identity(graph, wi.group(1), wi.group(2), sa, r)
            sources = [s for m in members if (s := self._sa(m, graph))]
            ops = [what for perm, what in IMPERSONATE if _allows(perms, excluded, perm)]
            if sa and ops and role_name != "roles/iam.workloadIdentityUser":
                for src in sources:
                    if src != sa:
                        graph.add_edge(
                            Edge(
                                src=src,
                                dst=sa,
                                kind=EdgeKind.USES_IDENTITY,
                                evidence=[r.ev],
                                confidence=conf,
                                note=f"{role_name} on the service account: can {ops[0]}",
                            )
                        )
            return
        if scope_kind == "project":
            store_ids, label = list(self.stores), "the project"
        else:
            store = self._first(target, scope_kind)
            if store is None or store.node_id is None:
                lit = literal(target)
                match = [
                    nid
                    for nid, s in self.stores.items()
                    if s.rtype == scope_kind
                    and lit
                    and lit.rsplit("/", 1)[-1] == self._name(s, DATASTORES[s.rtype][4])
                ]
                if not match:
                    return
                store_ids = match
            else:
                store_ids = [store.node_id]
            label = DATASTORES[scope_kind][2]
        sources = [s for m in members if (s := self._sa(m, graph))]
        for nid in store_ids:
            store = self.stores[nid]
            for perm, what in READ_PATHS[store.rtype]:
                if not _allows(perms, excluded, perm):
                    continue
                readable = perm in (
                    "storage.objects.get",
                    "bigquery.tables.getData",
                    "secretmanager.versions.access",
                )
                prevented = str(store.body.get("public_access_prevention", "")).lower() == "enforced"
                if public and readable and not prevented:
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=nid,
                            kind=EdgeKind.CAN_ACCESS,
                            evidence=[r.ev],
                            confidence=conf,
                            note=f"{role_name} granted to {public[0]}",
                        )
                    )
                for src in sources:
                    graph.add_edge(
                        Edge(
                            src=src,
                            dst=nid,
                            kind=EdgeKind.CAN_ACCESS,
                            evidence=[r.ev],
                            confidence=conf,
                            note=f"{role_name} on {label}: can {what}",
                        )
                    )
                break
        if scope_kind != "project":
            return
        for src in sources:
            if _allows(perms, excluded, PROJECT_ESCALATION):
                graph.add_node(
                    Node(id=PROJECT_OWNER_ID, kind=NodeKind.IDENTITY, name="GCP project owner", value=10)
                )
                graph.add_edge(
                    Edge(
                        src=src,
                        dst=PROJECT_OWNER_ID,
                        kind=EdgeKind.USES_IDENTITY,
                        evidence=[r.ev],
                        confidence=conf,
                        note=f"privilege escalation: {role_name} can rewrite the project's IAM policy",
                    )
                )
                for nid in self.stores:
                    graph.add_edge(
                        Edge(src=PROJECT_OWNER_ID, dst=nid, kind=EdgeKind.CAN_ACCESS, note="owner")
                    )
                continue
            ops = [what for perm, what in IMPERSONATE if _allows(perms, excluded, perm)]
            if ops:
                for sa in self.sas:
                    if sa != src:
                        graph.add_edge(
                            Edge(
                                src=src,
                                dst=sa,
                                kind=EdgeKind.USES_IDENTITY,
                                evidence=[r.ev],
                                confidence=conf,
                                note=f"{role_name} on the project: can {ops[0]} of any service account",
                            )
                        )

    def _workload_identity(self, graph: Graph, ns: str, name: str, sa: str, r: Res) -> None:
        said = f"k8s:serviceaccount:{ns}/{name}"
        graph.add_node(
            Node(id=said, kind=NodeKind.IDENTITY, name=f"ServiceAccount {ns}/{name}", evidence=[r.ev])
        )
        graph.add_edge(
            Edge(
                src=said,
                dst=sa,
                kind=EdgeKind.USES_IDENTITY,
                evidence=[r.ev],
                note="GKE Workload Identity (roles/iam.workloadIdentityUser)",
            )
        )

    # ------------------------------------------------------------------ exposure

    def _expose(
        self, graph: Graph, w: Res, ev_res: Res, note: str, conf: Confidence = Confidence.HIGH
    ) -> None:
        if w.node_id is None:
            return
        if w.rtype.startswith("google_cloud_run"):
            ingress = str(w.body.get("ingress", "")).upper()
            annotations = str(first_block(w.body.get("metadata")).get("annotations", ""))
            if "INTERNAL" in ingress or "internal" in annotations:
                return
        graph.add_node(internet())
        graph.add_edge(
            Edge(
                src=INTERNET_ID,
                dst=w.node_id,
                kind=EdgeKind.EXPOSES,
                evidence=[ev_res.ev],
                confidence=conf,
                note=note,
            )
        )

    def _public_acls(self, graph: Graph) -> None:
        for r in self.res.values():
            if (
                r.rtype == "google_cloud_run_v2_service"
                and r.node_id
                and truthy(r.body.get("invoker_iam_disabled"))
            ):
                self._expose(graph, r, r, "invoker_iam_disabled = true: no authentication")
            if r.rtype in (
                "google_storage_bucket_access_control",
                "google_storage_default_object_access_control",
            ):
                if str(r.body.get("entity", "")).lower() not in _PUBLIC_MEMBERS:
                    continue
                bucket = self._first(r.body.get("bucket"), "google_storage_bucket")
                if bucket and bucket.node_id:
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=bucket.node_id,
                            kind=EdgeKind.CAN_ACCESS,
                            evidence=[r.ev],
                            confidence=Confidence.MEDIUM,
                            note=f"ACL grants {r.body.get('entity')} "
                            "(ignored if uniform bucket-level access is on)",
                        )
                    )
            if r.rtype == "google_bigquery_dataset" and r.node_id:
                for a in list_blocks(r.body.get("access")):
                    who = str(a.get("special_group") or a.get("iam_member") or "")
                    if who.lower() in _PUBLIC_MEMBERS:
                        graph.add_node(internet())
                        graph.add_edge(
                            Edge(
                                src=INTERNET_ID,
                                dst=r.node_id,
                                kind=EdgeKind.CAN_ACCESS,
                                evidence=[r.ev],
                                note=f"dataset access granted to {who}",
                            )
                        )

    def _public_sql(self, graph: Graph) -> None:
        passwords = {
            ref
            for u in self.res.values()
            if u.rtype == "google_sql_user" and literal(u.body.get("password"))
            for ref in refs(u.body.get("instance"))
        }
        for key, r in self.res.items():
            if r.rtype != "google_sql_database_instance" or not r.node_id:
                continue
            ip = first_block(first_block(r.body.get("settings")).get("ip_configuration"))
            if str(ip.get("ipv4_enabled", "true")).lower() == "false":
                continue
            nets = [str(n.get("value")) for n in list_blocks(ip.get("authorized_networks"))]
            if "0.0.0.0/0" not in nets:
                continue
            ep = f"{r.node_id}:endpoint"
            graph.add_node(internet())
            node = graph.add_node(
                Node(
                    id=ep,
                    kind=NodeKind.ENTRYPOINT,
                    name=f"Public IP of {self._name(r)}",
                    attrs={"tf_range": r.tf_range},
                    evidence=[r.ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=INTERNET_ID,
                    dst=ep,
                    kind=EdgeKind.EXPOSES,
                    evidence=[r.ev],
                    note="authorized_networks includes 0.0.0.0/0",
                )
            )
            if key in passwords or literal(r.body.get("root_password")):
                node.weaknesses.append(
                    Weakness(
                        cls=WeaknessClass.CREDENTIAL_EXPOSURE,
                        title="database password is hardcoded in Terraform",
                        evidence=r.ev,
                    )
                )
            graph.add_edge(
                Edge(
                    src=ep,
                    dst=r.node_id,
                    kind=EdgeKind.CAN_ACCESS,
                    evidence=[r.ev],
                    requires=[WeaknessClass.CREDENTIAL_EXPOSURE],
                    note="requires valid database credentials",
                )
            )

    def _vm_exposure(self, graph: Graph) -> None:
        rules: list[tuple[Res, list[str]]] = []
        for r in self.res.values():
            b = r.body
            if r.rtype != "google_compute_firewall" or truthy(b.get("disabled")):
                continue
            if str(b.get("direction", "INGRESS")).upper() != "INGRESS":
                continue
            if not ({"0.0.0.0/0", "::/0"} & set(list_of(b.get("source_ranges")))):
                continue
            allows = list_blocks(b.get("allow"))
            if allows:
                rules.append(
                    (r, [f"{a.get('protocol')}/{','.join(list_of(a.get('ports'))) or 'all'}" for a in allows])
                )
        for vm in self.res.values():
            if vm.rtype != "google_compute_instance" or not vm.node_id:
                continue
            nics = list_blocks(vm.body.get("network_interface"))
            if not any("access_config" in n for n in nics):
                continue  # no external IP
            tags = set(list_of(vm.body.get("tags")))
            vm_sa = self._sa(first_block(vm.body.get("service_account")).get("email"), graph)
            networks = {str(n.get("network", "default")) for n in nics}
            for fw, ports in rules:
                target_tags = set(list_of(fw.body.get("target_tags")))
                target_sas = [self._sa(s, graph) for s in list_of(fw.body.get("target_service_accounts"))]
                if target_tags and not (target_tags & tags):
                    continue
                if target_sas and vm_sa not in target_sas:
                    continue
                fw_net = str(fw.body.get("network", "default"))
                same = fw_net in networks or any(x in fw_net or fw_net in x for x in networks)
                graph.add_node(internet())
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=vm.node_id,
                        kind=EdgeKind.EXPOSES,
                        evidence=[fw.ev],
                        confidence=Confidence.HIGH if same else Confidence.MEDIUM,
                        note=f"external IP and firewall {self._name(fw)} open to 0.0.0.0/0 "
                        f"on {', '.join(ports)}",
                    )
                )
