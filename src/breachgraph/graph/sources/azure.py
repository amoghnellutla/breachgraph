"""Terraform (azurerm) -> Azure exposure, managed identities, effective role assignments, data stores.

Same model as the AWS source: an identity reaches a data store only when a role assignment whose
scope covers that store grants an action that yields the data (a data action such as reading blobs,
or a control-plane action such as listing the account keys), with NotActions applied. Compute
reaches its identity only through code execution or SSRF to IMDS. Attribute names follow the
azurerm provider 3.x/4.x docs (checked 2026-10).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
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
from breachgraph.graph.sources.hcl import literal, refs, truthy
from breachgraph.graph.sources.tfload import Res, attr_refs, code_paths, first_block, list_blocks, list_of

SUBSCRIPTION_OWNER_ID = "azure:subscription-owner"
K8S_NODES_ID = "k8s:host:nodes"

# Data stores: type -> (node kind, value 0-10, label, relational database)
DATASTORES: dict[str, tuple[NodeKind, int, str, bool]] = {
    "azurerm_storage_account": (NodeKind.DATASTORE, 7, "Storage account", False),
    "azurerm_key_vault": (NodeKind.SECRET, 8, "Key Vault", False),
    "azurerm_mssql_server": (NodeKind.DATASTORE, 9, "Azure SQL server", True),
    "azurerm_postgresql_flexible_server": (NodeKind.DATASTORE, 9, "PostgreSQL flexible server", True),
    "azurerm_mysql_flexible_server": (NodeKind.DATASTORE, 9, "MySQL flexible server", True),
    "azurerm_cosmosdb_account": (NodeKind.DATASTORE, 8, "Cosmos DB account", False),
}

# How an identity gets the data, per store type: (plane, operation, what it lets the holder do).
# "data" operations are matched against a role's DataActions, "action" ones against its Actions.
READ_PATHS: dict[str, list[tuple[str, str, str]]] = {
    "azurerm_storage_account": [
        ("data", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "read blobs"),
        ("action", "Microsoft.Storage/storageAccounts/listKeys/action", "list the account keys"),
    ],
    "azurerm_key_vault": [
        ("data", "Microsoft.KeyVault/vaults/secrets/getSecret/action", "read secrets"),
    ],
    "azurerm_mssql_server": [
        ("action", "Microsoft.Sql/servers/write", "reset the server's admin password"),
    ],
    "azurerm_postgresql_flexible_server": [
        ("action", "Microsoft.DBforPostgreSQL/flexibleServers/write", "reset the server's admin password"),
    ],
    "azurerm_mysql_flexible_server": [
        ("action", "Microsoft.DBforMySQL/flexibleServers/write", "reset the server's admin password"),
    ],
    "azurerm_cosmosdb_account": [
        ("action", "Microsoft.DocumentDB/databaseAccounts/listKeys/action", "list the account keys"),
        ("action", "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action", "read the read-only keys"),
    ],
}
# Vaults in access-policy mode (not RBAC): whoever can edit the vault can grant itself secrets.
VAULT_POLICY_PATH = (
    "action",
    "Microsoft.KeyVault/vaults/accessPolicies/write",
    "grant itself an access policy",
)
ESCALATION = "Microsoft.Authorization/roleAssignments/write"

_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"
# Built-in roles that matter for data access or escalation: (Actions, NotActions, DataActions).
ROLES: dict[str, tuple[list[str], list[str], list[str]]] = {
    "Owner": (["*"], [], []),
    "Contributor": (
        ["*"],
        [
            "Microsoft.Authorization/*/Delete",
            "Microsoft.Authorization/*/Write",
            "Microsoft.Authorization/elevateAccess/Action",
        ],
        [],
    ),
    "Reader": (["*/read"], [], []),
    "User Access Administrator": (["*/read", "Microsoft.Authorization/*"], [], []),
    "Role Based Access Control Administrator": (
        [
            "*/read",
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/roleAssignments/delete",
        ],
        [],
        [],
    ),
    "Storage Account Contributor": (["Microsoft.Storage/storageAccounts/*"], [], []),
    "Storage Account Key Operator Service Role": (
        [
            "Microsoft.Storage/storageAccounts/listkeys/action",
            "Microsoft.Storage/storageAccounts/regeneratekey/action",
        ],
        [],
        [],
    ),
    "Storage Blob Data Owner": ([], [], [f"{_BLOBS}/*"]),
    "Storage Blob Data Contributor": ([], [], [f"{_BLOBS}/read", f"{_BLOBS}/write", f"{_BLOBS}/delete"]),
    "Storage Blob Data Reader": ([], [], [f"{_BLOBS}/read"]),
    "Key Vault Administrator": ([], [], ["Microsoft.KeyVault/vaults/*"]),
    "Key Vault Secrets Officer": ([], [], ["Microsoft.KeyVault/vaults/secrets/*"]),
    "Key Vault Secrets User": (
        [],
        [],
        [
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        ],
    ),
    "Key Vault Contributor": (["Microsoft.KeyVault/*"], [], []),
    "DocumentDB Account Contributor": (["Microsoft.DocumentDb/databaseAccounts/*"], [], []),
    "Cosmos DB Account Reader Role": (
        ["Microsoft.DocumentDB/*/read", "Microsoft.DocumentDB/databaseAccounts/readonlykeys/action"],
        [],
        [],
    ),
    "SQL Server Contributor": (["Microsoft.Sql/servers/*"], [], []),
}

# Compute: type -> (label, platform)
COMPUTE: dict[str, tuple[str, str]] = {
    "azurerm_linux_virtual_machine": ("VM", "azure-vm"),
    "azurerm_windows_virtual_machine": ("VM", "azure-vm"),
    "azurerm_virtual_machine": ("VM", "azure-vm"),
    "azurerm_linux_virtual_machine_scale_set": ("VM scale set", "azure-vm"),
    "azurerm_windows_virtual_machine_scale_set": ("VM scale set", "azure-vm"),
    "azurerm_orchestrated_virtual_machine_scale_set": ("VM scale set", "azure-vm"),
    "azurerm_linux_web_app": ("App Service app", "app-service"),
    "azurerm_windows_web_app": ("App Service app", "app-service"),
    "azurerm_linux_function_app": ("Function app", "app-service"),
    "azurerm_windows_function_app": ("Function app", "app-service"),
    "azurerm_container_app": ("Container app", "container-app"),
    # azurerm 2.x/3.x names, still common
    "azurerm_function_app": ("Function app", "app-service"),
    "azurerm_app_service": ("App Service app", "app-service"),
    # Runs runbooks as its managed identity; reachable by whoever can start jobs on it.
    "azurerm_automation_account": ("Automation account", "automation"),
}
# Who can run code on a compute resource, and so act as its managed identities.
CODE_EXEC: dict[str, str] = {
    "azure-vm": "Microsoft.Compute/virtualMachines/runCommand/action",
    "app-service": "Microsoft.Web/sites/write",
    "container-app": "Microsoft.App/containerApps/write",
    "automation": "Microsoft.Automation/automationAccounts/jobs/write",
}
_OPEN_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}
_SUBJECT_RE = re.compile(r"system:serviceaccount:([\w.-]+):([\w.-]+)")


def _matches(patterns: list[str], op: str) -> bool:
    return any(fnmatch.fnmatchcase(op.lower(), p.lower()) for p in patterns)


class _Role:
    def __init__(
        self, name: str, actions: list[str], not_actions: list[str], data: list[str], not_data: list[str]
    ):
        self.name, self.actions, self.not_actions, self.data, self.not_data = (
            name,
            actions,
            not_actions,
            data,
            not_data,
        )

    def allows(self, plane: str, op: str) -> bool:
        if plane == "data":
            return _matches(self.data, op) and not _matches(self.not_data, op)
        return _matches(self.actions, op) and not _matches(self.not_actions, op)


class AzureTerraform:
    def __init__(self, res: dict[str, Res]) -> None:
        self.all_res = res  # every block, for provider-neutral ones such as data.archive_file
        self.res = {k: v for k, v in res.items() if v.rtype.startswith("azurerm_")}
        self.system_ids: dict[str, str] = {}  # compute key -> system-assigned identity node
        self.kubelet_ids: dict[str, str] = {}  # AKS cluster key -> kubelet identity node
        self.stores: dict[str, Res] = {}  # node id -> data store resource
        self.compute_identities: dict[str, list[str]] = {}  # compute node id -> its identity nodes
        self.skipped: list[str] = []

    def collect(self, graph: Graph, skipped: list[str]) -> None:
        if not self.res:
            return
        self.skipped = skipped
        self._datastores(graph)
        self._identities(graph)
        self._compute(graph)
        self._aks(graph)
        self._role_assignments(graph)
        self._vault_access_policies(graph)
        self._federated_credentials(graph)
        self._public_storage(graph)
        self._public_databases(graph)
        self._vm_exposure(graph)
        self._app_exposure(graph)

    # ------------------------------------------------------------------ helpers

    def _get(self, ref: str, *types: str) -> Res | None:
        r = self.res.get(ref)
        return r if r and (not types or r.rtype in types) else None

    def _first(self, value: Any, *types: str) -> Res | None:
        for ref in refs(value):
            r = self._get(ref, *types)
            if r:
                return r
        return None

    def _name(self, r: Res) -> str:
        return literal(r.body.get("name")) or r.name

    def _rg(self, value: Any) -> str | None:
        """Resource group name from a literal or an azurerm_resource_group reference."""
        rg = self._first(value, "azurerm_resource_group")
        if rg:
            return self._name(rg).lower()
        lit = literal(value)
        if lit:
            return lit.lower()
        # The same variable names the same group, whatever its value: "var.resource_group".
        m = re.fullmatch(r"\$\{((?:var|local)\.[\w-]+)\}", str(value))
        return m.group(1) if m else None

    # ------------------------------------------------------------------ data stores

    def _datastores(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if key.startswith("data.") or r.rtype not in DATASTORES:
                continue
            kind, value, label, relational = DATASTORES[r.rtype]
            name = self._name(r)
            r.node_id = f"azure:{r.rtype.removeprefix('azurerm_')}:{name}"
            rbac = truthy(r.body.get("enable_rbac_authorization")) or truthy(
                r.body.get("rbac_authorization_enabled")
            )
            graph.add_node(
                Node(
                    id=r.node_id,
                    kind=kind,
                    name=f"{label} {name}",
                    value=value,
                    attrs={
                        "platform": "azure",
                        "tf": key,
                        "tf_range": r.tf_range,
                        "rg": self._rg(r.body.get("resource_group_name")),
                        "relational": relational,
                        "rbac": rbac,
                    },
                    evidence=[r.ev],
                )
            )
            self.stores[r.node_id] = r

    def _read_paths(self, r: Res, graph: Graph) -> list[tuple[str, str, str]]:
        paths = list(READ_PATHS[r.rtype])
        if r.rtype == "azurerm_key_vault" and r.node_id and not graph.nodes[r.node_id].attrs.get("rbac"):
            paths.append(VAULT_POLICY_PATH)
        return paths

    # ------------------------------------------------------------------ identities and compute

    def _identity_node(self, graph: Graph, node_id: str, name: str, ev: Evidence) -> str:
        graph.add_node(
            Node(id=node_id, kind=NodeKind.IDENTITY, name=name, attrs={"platform": "azure"}, evidence=[ev])
        )
        return node_id

    def _identities(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if r.rtype == "azurerm_user_assigned_identity" and not key.startswith("data."):
                name = self._name(r)
                r.node_id = self._identity_node(
                    graph, f"azure:identity:{name}", f"Managed identity {name}", r.ev
                )

    def _compute(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if key.startswith("data.") or r.rtype not in COMPUTE:
                continue
            label, platform = COMPUTE[r.rtype]
            name = self._name(r)
            r.node_id = f"azure:{r.rtype.removeprefix('azurerm_')}:{name}"
            node = graph.add_node(
                Node(
                    id=r.node_id,
                    kind=NodeKind.WORKLOAD,
                    name=f"{label} {name}",
                    attrs={
                        "platform": platform,
                        "tf_range": r.tf_range,
                        "images": self._images(r),
                        "code_paths": code_paths(self.all_res, r) if platform == "app-service" else [],
                    },
                    evidence=[r.ev],
                )
            )
            if platform == "azure-vm":
                node.attrs["metadata_header"] = "the required Metadata: true header"
                node.weaknesses.append(
                    Weakness(
                        cls=WeaknessClass.METADATA_REACHABLE,
                        evidence=r.ev,
                        title="Azure Instance Metadata Service (169.254.169.254) issues tokens for the VM's "
                        "managed identities",
                    )
                )
            # App Service and Container Apps serve tokens from IDENTITY_ENDPOINT, which needs the
            # secret IDENTITY_HEADER: an SSRF alone cannot get one, so no metadata weakness there.
            ident = first_block(r.body.get("identity"))
            targets: list[str] = []
            if "systemassigned" in str(ident.get("type", "")).lower().replace(" ", "").replace(",", ""):
                sid = self._identity_node(
                    graph, f"{r.node_id}/system-identity", f"System-assigned identity of {label} {name}", r.ev
                )
                self.system_ids[key] = sid
                targets.append(sid)
            for ref in refs(ident.get("identity_ids")):
                uai = self._get(ref, "azurerm_user_assigned_identity")
                if uai and uai.node_id:
                    targets.append(uai.node_id)
            self.compute_identities[r.node_id] = targets
            for t in targets:
                graph.add_edge(
                    Edge(
                        src=r.node_id,
                        dst=t,
                        kind=EdgeKind.USES_IDENTITY,
                        requires=CONTROL,
                        evidence=[r.ev],
                        note="using the managed identity requires running code in the workload",
                    )
                )

    def _images(self, r: Res) -> list[str]:
        if r.rtype == "azurerm_container_app":
            template = first_block(r.body.get("template"))
            return [
                str(c["image"]) for c in list_blocks(template.get("container")) if literal(c.get("image"))
            ]
        fx = str(first_block(r.body.get("site_config")).get("linux_fx_version", ""))
        if fx.upper().startswith("DOCKER|"):
            return [fx.split("|", 1)[1]]
        stack = first_block(first_block(r.body.get("site_config")).get("application_stack"))
        image = literal(stack.get("docker_image_name") or stack.get("docker_image"))
        return [image] if image else []

    def _aks(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if r.rtype != "azurerm_kubernetes_cluster" or key.startswith("data."):
                continue
            name = self._name(r)
            kubelet = first_block(r.body.get("kubelet_identity"))
            uai = self._first(kubelet.get("user_assigned_identity_id"), "azurerm_user_assigned_identity")
            if uai and uai.node_id:
                kid = uai.node_id
            else:
                kid = self._identity_node(
                    graph, f"azure:identity:{name}/kubelet", f"AKS kubelet identity of {name}", r.ev
                )
            self.kubelet_ids[key] = kid
            graph.add_node(
                Node(id=K8S_NODES_ID, kind=NodeKind.HOST, name="Kubernetes worker nodes", evidence=[r.ev])
            )
            graph.add_edge(
                Edge(
                    src=K8S_NODES_ID,
                    dst=kid,
                    kind=EdgeKind.USES_IDENTITY,
                    evidence=[r.ev],
                    note="AKS kubelet identity via the node's IMDS",
                )
            )

    def _principals(self, value: Any) -> list[str]:
        """Identity nodes a principal_id / object_id expression refers to."""
        out: list[str] = []
        for ref, tail in attr_refs(value):
            r = self.res.get(ref)
            if r is None:
                continue
            if r.rtype == "azurerm_user_assigned_identity" and r.node_id and "principal_id" in tail:
                out.append(r.node_id)
            elif (
                r.rtype == "azurerm_kubernetes_cluster"
                and "kubelet_identity" in tail
                and ref in self.kubelet_ids
            ):
                out.append(self.kubelet_ids[ref])
            elif "identity" in tail and "principal_id" in tail and ref in self.system_ids:
                out.append(self.system_ids[ref])
        return out

    # ------------------------------------------------------------------ permissions

    def _role(self, r: Res) -> _Role | None:
        name = literal(r.body.get("role_definition_name"))
        if name:
            if name in ROLES:
                return _Role(name, *ROLES[name], [])
            self.skipped.append(f"{r.ev.label()}: Azure role '{name}' is not modeled, assignment ignored")
            return None
        custom = self._first(r.body.get("role_definition_id"), "azurerm_role_definition")
        if custom:
            perms = list_blocks(custom.body.get("permissions"))
            if not perms:  # `data "azurerm_role_definition"` looking up a built-in role by name
                looked_up = literal(custom.body.get("name"))
                if looked_up in ROLES:
                    return _Role(looked_up, *ROLES[looked_up], [])
                self.skipped.append(
                    f"{r.ev.label()}: Azure role '{looked_up}' is not modeled, assignment ignored"
                )
                return None
            return _Role(
                self._name(custom),
                [a for p in perms for a in list_of(p.get("actions"))],
                [a for p in perms for a in list_of(p.get("not_actions"))],
                [a for p in perms for a in list_of(p.get("data_actions"))],
                [a for p in perms for a in list_of(p.get("not_data_actions"))],
            )
        self.skipped.append(f"{r.ev.label()}: role definition could not be resolved statically")
        return None

    def _scope(self, value: Any) -> tuple[str, Callable[[Res], bool]] | None:
        """(label, which resources it covers) for a role assignment scope; None if unknown."""
        for ref in refs(value):
            r = self.res.get(ref)
            if r is None:
                continue
            if r.node_id and (r.node_id in self.stores or r.rtype in COMPUTE):
                label = DATASTORES[r.rtype][2] if r.rtype in DATASTORES else COMPUTE[r.rtype][0]
                return f"{label} {self._name(r)}", lambda x, r=r: x is r
            if r.rtype in ("azurerm_storage_container", "azurerm_key_vault_secret"):
                parent = self._first(
                    [
                        r.body.get("storage_account_name"),
                        r.body.get("storage_account_id"),
                        r.body.get("key_vault_id"),
                    ],
                    "azurerm_storage_account",
                    "azurerm_key_vault",
                )
                if parent and parent.node_id:
                    return f"{r.rtype.removeprefix('azurerm_')} {self._name(r)}", lambda x, p=parent: x is p
        text = value if isinstance(value, str) else str(value)
        if "azurerm_resource_group." in text or "/resourceGroups/" in text:
            m = re.search(r"/providers/Microsoft\.\w+/\w+/([^/${}]+)", text)
            if m:  # a resource ID written out by name
                target = m.group(1).lower()
                return f"resource {m.group(1)}", lambda x: self._name(x).lower() == target
            rg = self._first(value, "azurerm_resource_group")
            name = self._name(rg).lower() if rg else None
            if name is None:
                m = re.search(r"/resourceGroups/(?:([^/${}]+)|\$\{((?:var|local)\.[\w-]+)\})", text)
                name = (m.group(1).lower() if m.group(1) else m.group(2)) if m else None
            if name is None:
                return None
            return f"resource group {name}", lambda x: self._rg(x.body.get("resource_group_name")) == name
        if (
            "azurerm_subscription" in text
            or "managementGroups" in text
            or "azurerm_management_group" in text
            or re.fullmatch(r"/subscriptions/[^/]+/?", text)
        ):
            return "subscription", lambda _x: True
        return None

    def _role_assignments(self, graph: Graph) -> None:
        for key, r in self.res.items():
            if r.rtype != "azurerm_role_assignment" or key.startswith("data."):
                continue
            principals = self._principals(r.body.get("principal_id"))
            if not principals:
                continue  # a user/group/SP defined outside Terraform: not reachable from a workload
            role = self._role(r)
            if role is None:
                continue
            scope = self._scope(r.body.get("scope"))
            if scope is None:
                self.skipped.append(f"{r.ev.label()}: role assignment scope could not be resolved statically")
                continue
            label, covers = scope
            store_ids = [nid for nid, st in self.stores.items() if covers(st)]
            computes = [c for c in self.res.values() if c.rtype in COMPUTE and c.node_id and covers(c)]
            cond = Confidence.MEDIUM if r.body.get("condition") else Confidence.HIGH
            for pid in principals:
                self._lateral(graph, pid, role, label, computes, r, cond)
                if role.allows("action", ESCALATION):
                    if label == "subscription":
                        self._subscription_owner(graph, pid, r, role, cond)
                        continue
                    for sid in store_ids:
                        graph.add_edge(
                            Edge(
                                src=pid,
                                dst=sid,
                                kind=EdgeKind.CAN_ACCESS,
                                evidence=[r.ev],
                                confidence=cond,
                                note=f"{role.name} on {label}: can assign itself any role there",
                            )
                        )
                    continue
                for sid in store_ids:
                    store = self.stores[sid]
                    for plane, op, what in self._read_paths(store, graph):
                        if role.allows(plane, op):
                            graph.add_edge(
                                Edge(
                                    src=pid,
                                    dst=sid,
                                    kind=EdgeKind.CAN_ACCESS,
                                    evidence=[r.ev],
                                    confidence=cond,
                                    note=f"{role.name} on {label}: can {what}",
                                )
                            )
                            break

    def _lateral(
        self, graph: Graph, pid: str, role: _Role, label: str, computes: list[Res], r: Res, cond: Confidence
    ) -> None:
        """Running code on a compute resource (VM run command, app deployment, runbook job) lets
        the holder act as that resource's managed identities: classic Azure privilege escalation."""
        for c in computes:
            action = CODE_EXEC.get(COMPUTE[c.rtype][1])
            if action is None or not role.allows("action", action):
                continue
            for ident in self.compute_identities.get(c.node_id or "", []):
                if ident != pid:
                    graph.add_edge(
                        Edge(
                            src=pid,
                            dst=ident,
                            kind=EdgeKind.USES_IDENTITY,
                            evidence=[r.ev],
                            confidence=cond,
                            note=f"{role.name} on {label}: can run code on {COMPUTE[c.rtype][0]} "
                            f"{self._name(c)} ({action}) and act as its identity",
                        )
                    )

    def _subscription_owner(self, graph: Graph, pid: str, r: Res, role: _Role, cond: Confidence) -> None:
        graph.add_node(
            Node(id=SUBSCRIPTION_OWNER_ID, kind=NodeKind.IDENTITY, name="Azure subscription owner", value=10)
        )
        graph.add_edge(
            Edge(
                src=pid,
                dst=SUBSCRIPTION_OWNER_ID,
                kind=EdgeKind.USES_IDENTITY,
                evidence=[r.ev],
                confidence=cond,
                note=f"privilege escalation: {role.name} on the subscription can assign itself any role",
            )
        )
        for sid in self.stores:
            graph.add_edge(Edge(src=SUBSCRIPTION_OWNER_ID, dst=sid, kind=EdgeKind.CAN_ACCESS, note="owner"))

    def _vault_access_policies(self, graph: Graph) -> None:
        policies: list[tuple[str, Res, dict[str, Any]]] = []  # (vault node, evidence, policy)
        for r in self.res.values():
            if r.rtype == "azurerm_key_vault" and r.node_id:
                policies += [(r.node_id, r, p) for p in list_blocks(r.body.get("access_policy"))]
            elif r.rtype == "azurerm_key_vault_access_policy":
                vault = self._first(r.body.get("key_vault_id"), "azurerm_key_vault")
                if vault and vault.node_id:
                    policies.append((vault.node_id, r, r.body))
        for vault_id, src, p in policies:
            if graph.nodes[vault_id].attrs.get("rbac"):
                continue  # access policies are ignored once a vault uses Azure RBAC
            perms = [x.lower() for x in list_of(p.get("secret_permissions"))]
            if "get" not in perms and "all" not in perms:
                continue
            for pid in self._principals(p.get("object_id")):
                graph.add_edge(
                    Edge(
                        src=pid,
                        dst=vault_id,
                        kind=EdgeKind.CAN_ACCESS,
                        evidence=[src.ev],
                        note="Key Vault access policy grants secret Get",
                    )
                )

    def _federated_credentials(self, graph: Graph) -> None:
        """AKS workload identity: a Kubernetes service account federated to a managed identity."""
        for r in self.res.values():
            if r.rtype != "azurerm_federated_identity_credential":
                continue
            uai = self._first(r.body.get("parent_id"), "azurerm_user_assigned_identity")
            if uai and uai.node_id and "token.actions.githubusercontent.com" in str(r.body.get("issuer", "")):
                # GitHub Actions OIDC: Azure matches the subject exactly (no wildcards).
                node = graph.nodes[uai.node_id]
                known = node.attrs.get("github_oidc_subs")
                node.attrs["github_oidc_subs"] = [
                    *(known if isinstance(known, list) else []),
                    str(r.body.get("subject", "")),
                ]
                continue
            m = _SUBJECT_RE.search(str(r.body.get("subject", "")))
            if not (uai and uai.node_id and m):
                continue
            said = f"k8s:serviceaccount:{m.group(1)}/{m.group(2)}"
            graph.add_node(
                Node(
                    id=said,
                    kind=NodeKind.IDENTITY,
                    name=f"ServiceAccount {m.group(1)}/{m.group(2)}",
                    evidence=[r.ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=said,
                    dst=uai.node_id,
                    kind=EdgeKind.USES_IDENTITY,
                    evidence=[r.ev],
                    note="Azure workload identity federated credential",
                )
            )

    # ------------------------------------------------------------------ exposure

    def _public_storage(self, graph: Graph) -> None:
        for r in self.res.values():
            if r.rtype != "azurerm_storage_container":
                continue
            access = str(r.body.get("container_access_type", "private")).lower()
            if access not in ("blob", "container"):
                continue
            acct = self._first(
                [r.body.get("storage_account_name"), r.body.get("storage_account_id")],
                "azurerm_storage_account",
            )
            if not (acct and acct.node_id):
                continue
            if str(acct.body.get("public_network_access_enabled", "true")).lower() == "false":
                continue
            allow = acct.body.get(
                "allow_nested_items_to_be_public", acct.body.get("allow_blob_public_access")
            )
            if allow is not None and not truthy(allow):
                continue
            graph.add_node(internet())
            graph.add_edge(
                Edge(
                    src=INTERNET_ID,
                    dst=acct.node_id,
                    kind=EdgeKind.CAN_ACCESS,
                    evidence=[r.ev],
                    confidence=Confidence.HIGH if allow is not None else Confidence.MEDIUM,
                    note=f"container {self._name(r)} allows anonymous '{access}' access"
                    + (
                        ""
                        if allow is not None
                        else " (allow_nested_items_to_be_public is left at its default)"
                    ),
                )
            )

    def _public_databases(self, graph: Graph) -> None:
        rules = {
            "azurerm_mssql_firewall_rule": "azurerm_mssql_server",
            "azurerm_postgresql_flexible_server_firewall_rule": "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server_firewall_rule": "azurerm_mysql_flexible_server",
        }
        for r in self.res.values():
            if r.rtype not in rules:
                continue
            span = (str(r.body.get("start_ip_address")), str(r.body.get("end_ip_address")))
            if span != ("0.0.0.0", "255.255.255.255"):  # noqa: S104  (an address range, not a bind)
                continue  # 0.0.0.0-0.0.0.0 means "Azure services", not the internet
            server = self._first([r.body.get("server_id"), r.body.get("server_name")], rules[r.rtype])
            if not (server and server.node_id):
                continue
            if str(server.body.get("public_network_access_enabled", "true")).lower() == "false":
                continue
            ep = f"{server.node_id}:endpoint"
            graph.add_node(internet())
            node = graph.add_node(
                Node(
                    id=ep,
                    kind=NodeKind.ENTRYPOINT,
                    name=f"Public endpoint of {self._name(server)}",
                    attrs={"tf_range": server.tf_range},
                    evidence=[server.ev],
                )
            )
            graph.add_edge(
                Edge(
                    src=INTERNET_ID,
                    dst=ep,
                    kind=EdgeKind.EXPOSES,
                    evidence=[r.ev],
                    note="firewall rule allows 0.0.0.0-255.255.255.255",
                )
            )
            if literal(
                server.body.get("administrator_login_password") or server.body.get("administrator_password")
            ):
                node.weaknesses.append(
                    Weakness(
                        cls=WeaknessClass.CREDENTIAL_EXPOSURE,
                        title="database admin password is hardcoded in Terraform",
                        evidence=server.ev,
                    )
                )
            graph.add_edge(
                Edge(
                    src=ep,
                    dst=server.node_id,
                    kind=EdgeKind.CAN_ACCESS,
                    evidence=[server.ev],
                    requires=[WeaknessClass.CREDENTIAL_EXPOSURE],
                    note="requires valid database credentials",
                )
            )

    def _nsg_rules(self) -> dict[str, list[str]]:
        """NSG key -> ports opened to the internet by inbound Allow rules."""
        open_ports: dict[str, list[str]] = {}

        def check(nsg_key: str, rule: dict[str, Any]) -> None:
            sources = [rule.get("source_address_prefix"), *list_of(rule.get("source_address_prefixes"))]
            if (
                str(rule.get("direction", "")).lower() == "inbound"
                and str(rule.get("access", "")).lower() == "allow"
                and any(str(s).lower() in _OPEN_SOURCES for s in sources if s)
            ):
                ports = [rule.get("destination_port_range"), *list_of(rule.get("destination_port_ranges"))]
                open_ports.setdefault(nsg_key, []).extend(str(p) for p in ports if p)

        for key, r in self.res.items():
            if r.rtype == "azurerm_network_security_group":
                open_ports.setdefault(key, [])
                for rule in list_blocks(r.body.get("security_rule")):
                    check(key, rule)
        for r in self.res.values():
            if r.rtype == "azurerm_network_security_rule":
                nsg = self._first(r.body.get("network_security_group_name"), "azurerm_network_security_group")
                if nsg:
                    check(next(k for k, v in self.res.items() if v is nsg), r.body)
        return open_ports

    def _vm_exposure(self, graph: Graph) -> None:
        nsgs = self._nsg_rules()
        nic_nsg: dict[str, list[str]] = {}
        subnet_nsg: dict[str, list[str]] = {}
        for r in self.res.values():
            if r.rtype == "azurerm_network_interface_security_group_association":
                for nic_key in refs(r.body.get("network_interface_id")):
                    nic_nsg.setdefault(nic_key, []).extend(refs(r.body.get("network_security_group_id")))
            elif r.rtype == "azurerm_subnet_network_security_group_association":
                for sn in refs(r.body.get("subnet_id")):
                    subnet_nsg.setdefault(sn, []).extend(refs(r.body.get("network_security_group_id")))
        for vm in self.res.values():
            if not vm.node_id or COMPUTE.get(vm.rtype, ("", ""))[1] != "azure-vm":
                continue
            for nic_ref in refs(vm.body.get("network_interface_ids")):
                nic = self._get(nic_ref, "azurerm_network_interface")
                if nic is None:
                    continue
                configs = list_blocks(nic.body.get("ip_configuration"))
                pips = [
                    pip
                    for c in configs
                    if (pip := self._first(c.get("public_ip_address_id"), "azurerm_public_ip"))
                ]
                if not pips:
                    continue
                applied = nic_nsg.get(nic_ref, []) + [
                    n for c in configs for sn in refs(c.get("subnet_id")) for n in subnet_nsg.get(sn, [])
                ]
                applied = [n for n in applied if n in nsgs]
                if applied:
                    if not all(nsgs[n] for n in applied):
                        continue  # every NSG on the path (NIC and subnet) must allow the traffic
                    ports = sorted({p for n in applied for p in nsgs[n]})
                    conf, note = (
                        Confidence.HIGH,
                        f"public IP and NSG open to the internet on {', '.join(ports)}",
                    )
                else:
                    sku = str(pips[0].body.get("sku", "")).lower()
                    if sku == "standard":
                        continue  # Standard public IPs drop inbound traffic unless an NSG allows it
                    conf = Confidence.MEDIUM if sku == "basic" else Confidence.LOW
                    note = "public IP with no NSG" + (
                        ": Basic SKU accepts all inbound traffic"
                        if sku == "basic"
                        else " (open if the IP is Basic SKU)"
                    )
                graph.add_node(internet())
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=vm.node_id,
                        kind=EdgeKind.EXPOSES,
                        evidence=[nic.ev],
                        confidence=conf,
                        note=note,
                    )
                )

    def _app_exposure(self, graph: Graph) -> None:
        for r in self.res.values():
            if not r.node_id or r.rtype not in COMPUTE:
                continue
            platform = COMPUTE[r.rtype][1]
            if platform == "container-app":
                ingress = first_block(r.body.get("ingress"))
                if truthy(ingress.get("external_enabled")):
                    graph.add_node(internet())
                    graph.add_edge(
                        Edge(
                            src=INTERNET_ID,
                            dst=r.node_id,
                            kind=EdgeKind.EXPOSES,
                            evidence=[r.ev],
                            note="Container App ingress external_enabled = true",
                        )
                    )
            elif platform == "app-service":
                if str(r.body.get("public_network_access_enabled", "true")).lower() == "false":
                    continue
                restricted = bool(list_blocks(first_block(r.body.get("site_config")).get("ip_restriction")))
                graph.add_node(internet())
                graph.add_edge(
                    Edge(
                        src=INTERNET_ID,
                        dst=r.node_id,
                        kind=EdgeKind.EXPOSES,
                        evidence=[r.ev],
                        confidence=Confidence.LOW if restricted else Confidence.MEDIUM,
                        note="App Service apps are public by default"
                        + (" (ip_restriction rules limit who can reach it)" if restricted else ""),
                    )
                )
