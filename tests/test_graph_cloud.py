"""Azure and GCP Terraform sources, and end-to-end attack paths through them."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import INTERNET_ID, Confidence, Edge, EdgeKind, Graph, NodeKind, WeaknessClass
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import KubernetesSource
from breachgraph.graph.sources.terraform import TerraformSource
from tests.test_graph_paths import finding


def write(tmp: Path, name: str, text: str) -> None:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def tf(tmp: Path, hcl: str) -> tuple[Graph, list[str]]:
    write(tmp, "main.tf", hcl)
    g = Graph()
    ctx = SourceContext(root=tmp, exclude=[])
    TerraformSource().collect(ctx, g)
    return g, ctx.skipped


def edge(g: Graph, src: str, dst: str, kind: EdgeKind | None = None) -> Edge | None:
    return next(
        (e for e in g.edges if e.src == src and e.dst == dst and (kind is None or e.kind is kind)), None
    )


# ------------------------------------------------------------------ Azure

AZ_STORAGE = """
resource "azurerm_resource_group" "rg" {
  name     = "shop-prod"
  location = "westeurope"
}
resource "azurerm_storage_account" "data" {
  name                = "shopcustomerdata"
  resource_group_name = azurerm_resource_group.rg.name
}
"""
AZ_VM = """
resource "azurerm_linux_virtual_machine" "web" {
  name                  = "web"
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.web.id]
  identity {
    type = "SystemAssigned"
  }
}
"""
SA_NODE = "azure:storage_account:shopcustomerdata"
VM_IDENTITY = "azure:linux_virtual_machine:web/system-identity"


def assign(
    role: str, scope: str, principal: str = "azurerm_linux_virtual_machine.web.identity[0].principal_id"
) -> str:
    return f"""
resource "azurerm_role_assignment" "a" {{
  scope                = {scope}
  role_definition_name = "{role}"
  principal_id         = {principal}
}}
"""


def test_az_public_blob_container(tmp_path: Path) -> None:
    g, _ = tf(
        tmp_path,
        AZ_STORAGE
        + """
resource "azurerm_storage_container" "c" {
  name                  = "exports"
  storage_account_id    = azurerm_storage_account.data.id
  container_access_type = "blob"
}
""",
    )
    e = edge(g, INTERNET_ID, SA_NODE, EdgeKind.CAN_ACCESS)
    assert e is not None and e.confidence is Confidence.MEDIUM  # account flag left at default


def test_az_public_container_blocked_by_account(tmp_path: Path) -> None:
    g, _ = tf(
        tmp_path,
        AZ_STORAGE.replace(
            "resource_group_name = azurerm_resource_group.rg.name\n}",
            "resource_group_name = azurerm_resource_group.rg.name\n  allow_nested_items_to_be_public = false\n}",
            1,
        )
        + """
resource "azurerm_storage_container" "c" {
  name                  = "exports"
  storage_account_name  = azurerm_storage_account.data.name
  container_access_type = "container"
}
""",
    )
    assert edge(g, INTERNET_ID, SA_NODE) is None


def test_az_vm_identity_needs_code_execution(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM)
    e = edge(g, "azure:linux_virtual_machine:web", VM_IDENTITY, EdgeKind.USES_IDENTITY)
    assert e is not None and set(e.requires) == {
        WeaknessClass.CODE_EXECUTION,
        WeaknessClass.VULNERABLE_DEPENDENCY,
    }
    vm = g.nodes["azure:linux_virtual_machine:web"]
    assert vm.has({WeaknessClass.METADATA_REACHABLE}) and vm.attrs["metadata_header"]


def test_az_blob_reader_on_account(tmp_path: Path) -> None:
    g, _ = tf(
        tmp_path, AZ_STORAGE + AZ_VM + assign("Storage Blob Data Reader", "azurerm_storage_account.data.id")
    )
    e = edge(g, VM_IDENTITY, SA_NODE, EdgeKind.CAN_ACCESS)
    assert e is not None and "read blobs" in e.note


def test_az_reader_gets_no_data(tmp_path: Path) -> None:
    g, skipped = tf(tmp_path, AZ_STORAGE + AZ_VM + assign("Reader", "azurerm_resource_group.rg.id"))
    assert edge(g, VM_IDENTITY, SA_NODE) is None
    assert not skipped


def test_az_contributor_on_resource_group_lists_keys(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM + assign("Contributor", "azurerm_resource_group.rg.id"))
    e = edge(g, VM_IDENTITY, SA_NODE, EdgeKind.CAN_ACCESS)
    assert e is not None and "list the account keys" in e.note
    assert "azure:subscription-owner" not in g.nodes  # Contributor cannot assign roles


def test_az_scope_outside_resource_group(tmp_path: Path) -> None:
    hcl = AZ_STORAGE + AZ_VM + assign("Contributor", '"/subscriptions/0000/resourceGroups/other-rg"')
    g, _ = tf(tmp_path, hcl)
    assert edge(g, VM_IDENTITY, SA_NODE) is None


def test_az_owner_on_subscription_escalates(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + AZ_VM
        + 'data "azurerm_subscription" "current" {}\n'
        + assign("Owner", "data.azurerm_subscription.current.id")
    )
    g, _ = tf(tmp_path, hcl)
    e = edge(g, VM_IDENTITY, "azure:subscription-owner", EdgeKind.USES_IDENTITY)
    assert e is not None and "escalation" in e.note
    assert g.nodes["azure:subscription-owner"].value == 10
    assert edge(g, "azure:subscription-owner", SA_NODE) is not None


def test_az_custom_role_not_data_actions(tmp_path: Path) -> None:
    custom = """
resource "azurerm_role_definition" "blob" {
  name  = "blob-reader-%s"
  scope = azurerm_resource_group.rg.id
  permissions {
    data_actions     = ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"]
    not_data_actions = [%s]
  }
}
resource "azurerm_role_assignment" "a" {
  scope              = azurerm_storage_account.data.id
  role_definition_id = azurerm_role_definition.blob.role_definition_resource_id
  principal_id       = azurerm_linux_virtual_machine.web.identity[0].principal_id
}
"""
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM + custom % ("a", ""))
    assert edge(g, VM_IDENTITY, SA_NODE) is not None
    excluded = '"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"'
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM + custom % ("b", excluded))
    assert edge(g, VM_IDENTITY, SA_NODE) is None


def test_az_unknown_role_is_a_blind_spot(tmp_path: Path) -> None:
    _, skipped = tf(
        tmp_path, AZ_STORAGE + AZ_VM + assign("Some Custom Thing", "azurerm_storage_account.data.id")
    )
    assert any("not modeled" in s for s in skipped)


AZ_VAULT = """
resource "azurerm_key_vault" "kv" {
  name                = "shop-kv"
  resource_group_name = azurerm_resource_group.rg.name
  %s
}
"""


def test_az_key_vault_contributor_depends_on_permission_model(tmp_path: Path) -> None:
    kv = "azure:key_vault:shop-kv"
    policy_mode = (
        AZ_STORAGE + AZ_VM + AZ_VAULT % "" + assign("Key Vault Contributor", "azurerm_key_vault.kv.id")
    )
    g, _ = tf(tmp_path, policy_mode)
    e = edge(g, VM_IDENTITY, kv)
    assert e is not None and "access policy" in e.note
    rbac_mode = policy_mode.replace("  \n}", "  rbac_authorization_enabled = true\n}", 1)
    g, _ = tf(tmp_path, rbac_mode)
    assert g.nodes[kv].attrs["rbac"] is True
    assert edge(g, VM_IDENTITY, kv) is None
    g, _ = tf(tmp_path, rbac_mode.replace("Key Vault Contributor", "Key Vault Secrets User"))
    assert edge(g, VM_IDENTITY, kv) is not None


def test_az_key_vault_access_policy(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + AZ_VM
        + AZ_VAULT
        % """access_policy {
    tenant_id          = "t"
    object_id          = azurerm_linux_virtual_machine.web.identity[0].principal_id
    secret_permissions = ["Get", "List"]
  }"""
    )
    g, _ = tf(tmp_path, hcl)
    e = edge(g, VM_IDENTITY, "azure:key_vault:shop-kv")
    assert e is not None and "access policy" in e.note


SQL = """
resource "azurerm_mssql_server" "db" {
  name                         = "shop-sql"
  resource_group_name          = azurerm_resource_group.rg.name
  administrator_login_password = "Sup3rS3cret!"
}
resource "azurerm_mssql_firewall_rule" "all" {
  name             = "all"
  server_id        = azurerm_mssql_server.db.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "%s"
}
"""


def test_az_sql_open_firewall(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, AZ_STORAGE + SQL % "255.255.255.255")
    ep = "azure:mssql_server:shop-sql:endpoint"
    assert edge(g, INTERNET_ID, ep, EdgeKind.EXPOSES) is not None
    assert g.nodes[ep].has({WeaknessClass.CREDENTIAL_EXPOSURE})
    back = edge(g, ep, "azure:mssql_server:shop-sql")
    assert back is not None and back.requires == [WeaknessClass.CREDENTIAL_EXPOSURE]
    assert g.nodes["azure:mssql_server:shop-sql"].attrs["relational"] is True


def test_az_sql_azure_services_rule_is_not_internet(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, AZ_STORAGE + SQL % "0.0.0.0")  # noqa: S104
    assert "azure:mssql_server:shop-sql:endpoint" not in g.nodes


NET = """
resource "azurerm_public_ip" "web" {
  name = "web-ip"
  sku  = "%s"
}
resource "azurerm_network_interface" "web" {
  name = "web-nic"
  ip_configuration {
    name                 = "ipcfg"
    subnet_id            = azurerm_subnet.app.id
    public_ip_address_id = azurerm_public_ip.web.id
  }
}
"""
NSG = """
resource "azurerm_network_security_group" "%s" {
  name = "%s"
  security_rule {
    name                       = "web"
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "%s"
    destination_port_range     = "443"
  }
}
"""


def test_az_vm_public_ip_and_open_nsg(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + AZ_VM
        + NET % "Standard"
        + NSG % ("open", "open", "Internet")
        + """
resource "azurerm_network_interface_security_group_association" "a" {
  network_interface_id      = azurerm_network_interface.web.id
  network_security_group_id = azurerm_network_security_group.open.id
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    e = edge(g, INTERNET_ID, "azure:linux_virtual_machine:web", EdgeKind.EXPOSES)
    assert e is not None and e.confidence is Confidence.HIGH and "443" in e.note


def test_az_vm_subnet_nsg_must_also_allow(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + AZ_VM
        + NET % "Standard"
        + NSG % ("open", "open", "Internet")
        + NSG % ("closed", "closed", "10.0.0.0/8")
        + """
resource "azurerm_network_interface_security_group_association" "a" {
  network_interface_id      = azurerm_network_interface.web.id
  network_security_group_id = azurerm_network_security_group.open.id
}
resource "azurerm_subnet_network_security_group_association" "b" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.closed.id
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, INTERNET_ID, "azure:linux_virtual_machine:web") is None


def test_az_standard_public_ip_without_nsg_is_closed(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM + NET % "Standard")
    assert edge(g, INTERNET_ID, "azure:linux_virtual_machine:web") is None
    g, _ = tf(tmp_path, AZ_STORAGE + AZ_VM + NET % "Basic")
    e = edge(g, INTERNET_ID, "azure:linux_virtual_machine:web")
    assert e is not None and e.confidence is Confidence.MEDIUM


def test_az_workload_identity_and_aks_kubelet(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + """
resource "azurerm_user_assigned_identity" "api" {
  name                = "api-identity"
  resource_group_name = azurerm_resource_group.rg.name
}
resource "azurerm_federated_identity_credential" "api" {
  name      = "api"
  parent_id = azurerm_user_assigned_identity.api.id
  subject   = "system:serviceaccount:shop:api"
}
resource "azurerm_kubernetes_cluster" "aks" {
  name = "shop-aks"
}
resource "azurerm_role_assignment" "kubelet" {
  scope                = azurerm_storage_account.data.id
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_kubernetes_cluster.aks.kubelet_identity[0].object_id
}
resource "azurerm_role_assignment" "api" {
  scope                = azurerm_storage_account.data.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, "k8s:serviceaccount:shop/api", "azure:identity:api-identity") is not None
    assert edge(g, "azure:identity:api-identity", SA_NODE, EdgeKind.CAN_ACCESS) is not None
    kubelet = "azure:identity:shop-aks/kubelet"
    assert edge(g, "k8s:host:nodes", kubelet, EdgeKind.USES_IDENTITY) is not None
    assert edge(g, kubelet, SA_NODE, EdgeKind.CAN_ACCESS) is not None


def test_az_container_app_external_ingress(tmp_path: Path) -> None:
    hcl = """
resource "azurerm_container_app" "api" {
  name = "api"
  template {
    container {
      name  = "api"
      image = "shopacr.azurecr.io/api:1.4"
    }
  }
  ingress {
    external_enabled = true
    target_port      = 8080
  }
}
"""
    g, _ = tf(tmp_path, hcl)
    node = g.nodes["azure:container_app:api"]
    assert node.attrs["images"] == ["shopacr.azurecr.io/api:1.4"]
    assert not node.has({WeaknessClass.METADATA_REACHABLE})  # token endpoint needs IDENTITY_HEADER
    assert edge(g, INTERNET_ID, node.id, EdgeKind.EXPOSES) is not None


# ------------------------------------------------------------------ GCP

GCP_BASE = """
resource "google_service_account" "api" {
  account_id = "api-runner"
}
resource "google_storage_bucket" "data" {
  name = "shop-customer-data"
  %s
}
resource "google_secret_manager_secret" "db" {
  secret_id = "db-password"
}
resource "google_secret_manager_secret" "other" {
  secret_id = "other"
}
"""
GSA = "gcp:service_account:api-runner"
BUCKET = "gcp:storage_bucket:shop-customer-data"


def member(kind: str, role: str, who: str, extra: str = "") -> str:
    return f"""
resource "google_{kind}_iam_member" "m_{abs(hash((kind, role, who))) % 10**6}" {{
  {extra}
  role   = "{role}"
  member = {who}
}}
"""


SA_MEMBER = '"serviceAccount:${google_service_account.api.email}"'


def test_gcp_public_bucket(tmp_path: Path) -> None:
    hcl = GCP_BASE % "" + member(
        "storage_bucket",
        "roles/storage.objectViewer",
        '"allUsers"',
        "bucket = google_storage_bucket.data.name",
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, INTERNET_ID, BUCKET, EdgeKind.CAN_ACCESS) is not None
    prevented = GCP_BASE % 'public_access_prevention = "enforced"' + member(
        "storage_bucket",
        "roles/storage.objectViewer",
        '"allUsers"',
        "bucket = google_storage_bucket.data.name",
    )
    g, _ = tf(tmp_path, prevented)
    assert edge(g, INTERNET_ID, BUCKET) is None


def test_gcp_project_binding_reaches_bucket(tmp_path: Path) -> None:
    g, _ = tf(
        tmp_path, GCP_BASE % "" + member("project", "roles/storage.objectViewer", SA_MEMBER, 'project = "p"')
    )
    e = edge(g, GSA, BUCKET, EdgeKind.CAN_ACCESS)
    assert e is not None and "read objects" in e.note
    assert edge(g, GSA, "gcp:secret_manager_secret:db-password") is None


def test_gcp_viewer_gets_no_data_and_unknown_role_is_reported(tmp_path: Path) -> None:
    g, skipped = tf(tmp_path, GCP_BASE % "" + member("project", "roles/viewer", SA_MEMBER, 'project = "p"'))
    assert edge(g, GSA, BUCKET) is None and not skipped
    _, skipped = tf(tmp_path, GCP_BASE % "" + member("project", "roles/made.up", SA_MEMBER, 'project = "p"'))
    assert any("not modeled" in s for s in skipped)


def test_gcp_resource_level_secret_binding(tmp_path: Path) -> None:
    hcl = GCP_BASE % "" + member(
        "secret_manager_secret",
        "roles/secretmanager.secretAccessor",
        SA_MEMBER,
        "secret_id = google_secret_manager_secret.db.secret_id",
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, GSA, "gcp:secret_manager_secret:db-password") is not None
    assert edge(g, GSA, "gcp:secret_manager_secret:other") is None
    assert edge(g, GSA, BUCKET) is None


def test_gcp_owner_escalates(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, GCP_BASE % "" + member("project", "roles/owner", SA_MEMBER, 'project = "p"'))
    assert edge(g, GSA, "gcp:project-owner", EdgeKind.USES_IDENTITY) is not None
    assert edge(g, "gcp:project-owner", BUCKET) is not None


def test_gcp_impersonation(tmp_path: Path) -> None:
    hcl = (
        GCP_BASE % ""
        + """
resource "google_service_account" "admin" {
  account_id = "data-admin"
}
resource "google_service_account_iam_member" "tok" {
  service_account_id = google_service_account.admin.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.api.email}"
}
"""
        + member(
            "storage_bucket",
            "roles/storage.admin",
            '"serviceAccount:data-admin@p.iam.gserviceaccount.com"',
            "bucket = google_storage_bucket.data.name",
        )
    )
    g, _ = tf(tmp_path, hcl)
    e = edge(g, GSA, "gcp:service_account:data-admin", EdgeKind.USES_IDENTITY)
    assert e is not None and "mint access tokens" in e.note
    assert edge(g, "gcp:service_account:data-admin", BUCKET, EdgeKind.CAN_ACCESS) is not None


def test_gcp_custom_role(tmp_path: Path) -> None:
    hcl = (
        GCP_BASE % ""
        + """
resource "google_project_iam_custom_role" "reader" {
  role_id     = "bucketReader"
  permissions = ["storage.objects.get", "storage.objects.list"]
}
resource "google_project_iam_member" "custom" {
  project = "p"
  role    = google_project_iam_custom_role.reader.id
  member  = "serviceAccount:${google_service_account.api.email}"
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, GSA, BUCKET, EdgeKind.CAN_ACCESS) is not None


CLOUD_RUN = """
resource "google_cloud_run_v2_service" "api" {
  name    = "api"
  %s
  template {
    service_account = google_service_account.api.email
    containers {
      image = "gcr.io/shop/api:1.2"
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "public" {
  name   = google_cloud_run_v2_service.api.name
  role   = "roles/run.invoker"
  member = "allUsers"
}
"""


def test_gcp_cloud_run_public_invoker(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, GCP_BASE % "" + CLOUD_RUN % "")
    run = g.nodes["gcp:cloud_run_v2_service:api"]
    assert run.attrs["images"] == ["gcr.io/shop/api:1.2"]
    assert edge(g, INTERNET_ID, run.id, EdgeKind.EXPOSES) is not None
    e = edge(g, run.id, GSA, EdgeKind.USES_IDENTITY)
    assert e is not None and e.requires
    g, _ = tf(tmp_path, GCP_BASE % "" + CLOUD_RUN % 'ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"')
    assert edge(g, INTERNET_ID, "gcp:cloud_run_v2_service:api") is None


GCE = """
resource "google_compute_instance" "web" {
  name = "web"
  tags = ["web"]
  network_interface {
    network = "default"
    access_config {}
  }
  service_account {
    email  = google_service_account.api.email
    scopes = ["cloud-platform"]
  }
}
resource "google_compute_firewall" "https" {
  name          = "allow-https"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["%s"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
"""


def test_gcp_instance_exposed_by_firewall_tag(tmp_path: Path) -> None:
    g, _ = tf(tmp_path, GCP_BASE % "" + GCE % "web")
    e = edge(g, INTERNET_ID, "gcp:compute_instance:web", EdgeKind.EXPOSES)
    assert e is not None and "443" in e.note and e.confidence is Confidence.HIGH
    g, _ = tf(tmp_path, GCP_BASE % "" + GCE % "db")
    assert edge(g, INTERNET_ID, "gcp:compute_instance:web") is None


def test_gcp_cloud_sql_public_with_hardcoded_password(tmp_path: Path) -> None:
    hcl = """
resource "google_sql_database_instance" "db" {
  name = "shop-db"
  settings {
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}
resource "google_sql_user" "app" {
  name     = "app"
  instance = google_sql_database_instance.db.name
  password = "hunter22"
}
"""
    g, _ = tf(tmp_path, hcl)
    ep = "gcp:sql_database_instance:shop-db:endpoint"
    assert edge(g, INTERNET_ID, ep, EdgeKind.EXPOSES) is not None
    assert g.nodes[ep].has({WeaknessClass.CREDENTIAL_EXPOSURE})


def test_gke_workload_identity_both_sides(tmp_path: Path) -> None:
    hcl = (
        GCP_BASE % ""
        + """
resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.api.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:shop-prod.svc.id.goog[shop/api]"
}
resource "google_container_node_pool" "pool" {
  name = "pool"
  node_config {
    service_account = google_service_account.api.email
  }
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, "k8s:serviceaccount:shop/api", GSA, EdgeKind.USES_IDENTITY) is not None
    assert edge(g, "k8s:host:nodes", GSA, EdgeKind.USES_IDENTITY) is not None

    write(
        tmp_path,
        "k8s/sa.yaml",
        """apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: shop
  annotations:
    iam.gke.io/gcp-service-account: api-runner@shop-prod.iam.gserviceaccount.com
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: shop
spec:
  template:
    spec:
      serviceAccountName: api
      containers:
        - name: api
          image: gcr.io/shop/api:1.2
""",
    )
    g2 = Graph()
    KubernetesSource().collect(SourceContext(root=tmp_path, exclude=[]), g2)
    assert edge(g2, "k8s:serviceaccount:shop/api", GSA, EdgeKind.USES_IDENTITY) is not None


# ------------------------------------------------------------------ end to end

APP = """from flask import Flask, request
import os
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text


@app.route("/convert")
def convert():
    return os.popen("convert " + request.args["f"]).read()
"""


def project(tmp: Path, hcl: str) -> None:
    write(tmp, "api/app.py", APP)
    write(tmp, "api/Dockerfile", "FROM python:3.12-slim\nCOPY . .\nCMD python app.py\n")
    write(tmp, "infra/main.tf", hcl)


SSRF = finding("api/app.py", 10, "CWE-918", "SSRF", "ssrf")
CMDI = finding("api/app.py", 15, "CWE-78", "Command injection", "cmdi")


def test_gcp_cloud_run_path_to_bucket(tmp_path: Path) -> None:
    hcl = (
        GCP_BASE % ""
        + CLOUD_RUN % ""
        + member(
            "storage_bucket",
            "roles/storage.objectViewer",
            SA_MEMBER,
            "bucket = google_storage_bucket.data.name",
        )
    )
    project(tmp_path, hcl)
    res = build_attack_graph(tmp_path, [SSRF, CMDI], Config())
    to_bucket = [p for p in res.paths if p.target.id == BUCKET]
    assert {frozenset(p.weaknesses) for p in to_bucket} >= {frozenset({"cmdi"}), frozenset({"ssrf"})}
    ssrf = next(p for p in to_bucket if p.weaknesses == ["ssrf"])
    assert ssrf.confidence == Confidence.LOW  # the metadata server needs a Metadata-Flavor header

    no_weapons = build_attack_graph(tmp_path, [], Config())
    assert not any(p.target.id == BUCKET for p in no_weapons.paths)  # exposure alone is no path


def test_azure_container_app_path_to_storage(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + """
resource "azurerm_user_assigned_identity" "api" {
  name = "api-identity"
}
resource "azurerm_container_app" "api" {
  name = "api"
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.api.id]
  }
  template {
    container {
      name  = "api"
      image = "shopacr.azurecr.io/api:1.4"
    }
  }
  ingress {
    external_enabled = true
  }
}
"""
        + assign(
            "Storage Blob Data Reader",
            "azurerm_storage_account.data.id",
            "azurerm_user_assigned_identity.api.principal_id",
        )
    )
    project(tmp_path, hcl)
    res = build_attack_graph(tmp_path, [SSRF, CMDI], Config())
    to_store = [p for p in res.paths if p.target.id == SA_NODE]
    assert [p.weaknesses for p in to_store] == [["cmdi"]]  # SSRF can't get a token: IDENTITY_HEADER
    assert "azure:identity:api-identity" in to_store[0].nodes
    assert not any(p.target.id == SA_NODE for p in build_attack_graph(tmp_path, [], Config()).paths)


def test_datastore_kinds() -> None:
    from breachgraph.graph.sources import azure, gcp

    assert azure.DATASTORES["azurerm_key_vault"][0] is NodeKind.SECRET
    assert gcp.DATASTORES["google_secret_manager_secret"][0] is NodeKind.SECRET


def test_edges_needing_different_weaknesses_are_kept_apart() -> None:
    g = Graph()
    g.add_edge(Edge(src="a", dst="b", kind=EdgeKind.USES_IDENTITY, requires=[WeaknessClass.CODE_EXECUTION]))
    g.add_edge(Edge(src="a", dst="b", kind=EdgeKind.USES_IDENTITY, requires=[WeaknessClass.SSRF]))
    g.add_edge(Edge(src="a", dst="b", kind=EdgeKind.USES_IDENTITY, requires=[WeaknessClass.SSRF]))
    assert sorted(e.requires[0] for e in g.edges) == [WeaknessClass.CODE_EXECUTION, WeaknessClass.SSRF]


# ------------------------------------------------------------------ review regressions


def test_gcp_service_account_resource_path_form(tmp_path: Path) -> None:
    from breachgraph.graph.sources.gcp import sa_id

    assert (
        sa_id("projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com")
        == "gcp:service_account:deployer"
    )
    assert sa_id("serviceAccount:deployer@p.iam.gserviceaccount.com") == "gcp:service_account:deployer"


def test_az_builtin_role_looked_up_by_data_source(tmp_path: Path) -> None:
    hcl = (
        AZ_STORAGE
        + AZ_VM
        + """
data "azurerm_role_definition" "blob_reader" {
  name = "Storage Blob Data Reader"
}
resource "azurerm_role_assignment" "a" {
  scope              = azurerm_storage_account.data.id
  role_definition_id = data.azurerm_role_definition.blob_reader.id
  principal_id       = azurerm_linux_virtual_machine.web.identity[0].principal_id
}
"""
    )
    g, _ = tf(tmp_path, hcl)
    assert edge(g, VM_IDENTITY, SA_NODE, EdgeKind.CAN_ACCESS) is not None


def test_az_mysql_firewall_by_server_name(tmp_path: Path) -> None:
    hcl = """
resource "azurerm_mysql_flexible_server" "db" {
  name = "shop-mysql"
}
resource "azurerm_mysql_flexible_server_firewall_rule" "all" {
  name             = "all"
  server_name      = azurerm_mysql_flexible_server.db.name
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
"""
    g, _ = tf(tmp_path, hcl)
    assert (
        edge(g, INTERNET_ID, "azure:mysql_flexible_server:shop-mysql:endpoint", EdgeKind.EXPOSES) is not None
    )


def test_same_resource_names_in_different_modules(tmp_path: Path) -> None:
    write(tmp_path, "modules/a/main.tf", 'resource "aws_s3_bucket" "this" {\n  bucket = "bucket-a"\n}\n')
    write(tmp_path, "modules/b/main.tf", 'resource "aws_s3_bucket" "this" {\n  bucket = "bucket-b"\n}\n')
    g = Graph()
    TerraformSource().collect(SourceContext(root=tmp_path, exclude=[]), g)
    assert {"aws:s3_bucket:bucket-a", "aws:s3_bucket:bucket-b"} <= set(g.nodes)
