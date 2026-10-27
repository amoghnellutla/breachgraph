"""IAM users and AssumeRole chains, committed login credentials, and opt-in entry points."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from tests.test_graph_paths import finding


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def cfg(*entries: str) -> Config:
    return Config.model_validate({"attack_graph": {"entry_points": ["internet", *entries]}})


def routes(tmp: Path, config: Config, findings=()) -> list[list[str]]:  # type: ignore[no-untyped-def]
    return [p.nodes for p in build_attack_graph(tmp, list(findings), config).paths]


IAM = """
resource "aws_s3_bucket" "secrets" {
  bucket = "cg-secrets"
}
resource "aws_iam_user" "chris" {
  name = "chris"
}
resource "aws_iam_access_key" "chris" {
  user = aws_iam_user.chris.name
}
resource "aws_iam_group" "ops" {
  name = "ops"
}
resource "aws_iam_group_membership" "ops" {
  name  = "ops"
  group = aws_iam_group.ops.name
  users = [aws_iam_user.chris.name]
}
resource "aws_iam_group_policy" "assume" {
  group  = aws_iam_group.ops.name
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.manager.arn }] })
}
resource "aws_iam_role" "manager" {
  name = "manager"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = aws_iam_user.chris.arn }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy" "read" {
  role   = aws_iam_role.manager.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::cg-secrets/*" }] })
}
resource "aws_iam_role" "other" {
  name = "other"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
"""
CHAIN = [
    "internet",
    "entry:key:aws:iam_user:chris",
    "aws:iam_user:chris",
    "aws:iam_role:manager",
    "aws:s3_bucket:cg-secrets",
]


def test_leaked_key_entry_follows_group_policy_and_assume_role(tmp_path: Path) -> None:
    """CloudGoat: a user's group lets it assume a role whose trust names the user."""
    write(tmp_path, "main.tf", IAM)
    assert CHAIN in routes(tmp_path, cfg("credentials"))
    assert not any(r[-1] == "aws:s3_bucket:cg-secrets" for r in routes(tmp_path, Config()))  # opt-in only


def test_assume_role_needs_the_trust_policy_too(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", IAM.replace("Resource = aws_iam_role.manager.arn", 'Resource = "*"'))
    graph = build_attack_graph(tmp_path, [], cfg("credentials")).graph
    targets = {e.dst for e in graph.edges if e.src == "aws:iam_user:chris"}
    assert "aws:iam_role:manager" in targets  # trust names chris
    assert "aws:iam_role:other" not in targets  # allowed by policy, but its trust only admits EC2


AZ_VM = """
resource "azurerm_storage_account" "data" {
  name                = "goatdata"
  resource_group_name = var.resource_group
}
resource "azurerm_network_security_group" "ssh" {
  name = "ssh"
  security_rule {
    name                   = "ssh"
    direction              = "Inbound"
    access                 = "Allow"
    source_address_prefix  = "*"
    destination_port_range = "22"
  }
}
resource "azurerm_public_ip" "vm" {
  name = "vm-ip"
  sku  = "Standard"
}
resource "azurerm_network_interface" "vm" {
  name = "vm-nic"
  ip_configuration {
    name                 = "cfg"
    public_ip_address_id = azurerm_public_ip.vm.id
  }
}
resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.ssh.id
}
resource "azurerm_virtual_machine" "dev" {
  name                  = "dev-vm"
  resource_group_name   = var.resource_group
  network_interface_ids = [azurerm_network_interface.vm.id]
  identity {
    type = "SystemAssigned"
  }
  os_profile {
    admin_username = "azureuser"
    admin_password = "St0r95p@ssw0rd"
  }
  os_profile_linux_config {
    disable_password_authentication = %s
  }
}
resource "azurerm_role_assignment" "vm" {
  scope                = "/subscriptions/0/resourceGroups/${var.resource_group}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_virtual_machine.dev.identity.0.principal_id
}
"""


def test_committed_vm_password_is_a_way_in(tmp_path: Path) -> None:
    """AzureGoat: SSH open to the internet, a literal admin password, password login on."""
    write(tmp_path, "main.tf", AZ_VM % "false")
    chain = [
        "internet",
        "azure:virtual_machine:dev-vm",
        "azure:virtual_machine:dev-vm/system-identity",
        "azure:storage_account:goatdata",
    ]
    assert chain in routes(tmp_path, Config())
    write(tmp_path, "main.tf", AZ_VM % "true")  # key-only login: the password is useless
    assert chain not in routes(tmp_path, Config())


def test_committed_private_key_for_an_ec2_key_pair(tmp_path: Path) -> None:
    write(tmp_path, "keys/deploy.pub", "ssh-ed25519 AAAA deploy\n")
    write(
        tmp_path, "keys/deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    write(
        tmp_path,
        "main.tf",
        """
resource "aws_s3_bucket" "pii" {
  bucket = "pii"
}
resource "aws_key_pair" "deploy" {
  key_name   = "deploy"
  public_key = file("keys/deploy.pub")
}
resource "aws_iam_role" "web" {
  name = "web"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}
resource "aws_iam_instance_profile" "web" {
  role = aws_iam_role.web.name
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "web" {
  key_name                    = aws_key_pair.deploy.key_name
  iam_instance_profile        = aws_iam_instance_profile.web.name
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  associate_public_ip_address = true
}
""",
    )
    assert ["internet", "aws:ec2:web", "aws:iam_role:web", "aws:s3_bucket:pii"] in routes(tmp_path, Config())


POD = """apiVersion: apps/v1
kind: Deployment
metadata: {name: health, namespace: default}
spec:
  template:
    spec:
      containers:
        - name: app
          image: goat/health:1
          securityContext: {privileged: true}
"""


def test_cluster_entry_point_and_no_free_ride_on_escape(tmp_path: Path) -> None:
    """Kubernetes Goat: reaching a privileged pod is not running code in it."""
    write(tmp_path, "k8s/health.yaml", POD)
    write(tmp_path, "health/Dockerfile", "FROM golang\n")
    write(
        tmp_path,
        "health/main.go",
        'package main\nimport "github.com/gofiber/fiber/v2"\nfunc main() {\n  app := fiber.New()\n'
        '  app.Post("/", func(c *fiber.Ctx) error {\n    return run(c.FormValue("e"))\n  })\n}\n',
    )
    to_node = [r for r in routes(tmp_path, cfg("cluster")) if r[-1] == "k8s:host:nodes"]
    assert to_node == []  # privileged, reachable from inside the cluster, but no code execution
    cmdi = finding("health/main.go", 6, "CWE-78", "Command injection", "cmdi-health")
    to_node = [r for r in routes(tmp_path, cfg("cluster"), [cmdi]) if r[-1] == "k8s:host:nodes"]
    assert to_node and to_node[0][:2] == ["internet", "entry:cluster"]
    assert not [r for r in routes(tmp_path, Config(), [cmdi]) if r[-1] == "k8s:host:nodes"]  # not exposed


def test_a_path_needing_a_derived_weakness_does_not_hide_a_direct_one(tmp_path: Path) -> None:
    """A committed password has no scanner fingerprint; its path must not replace the anonymous
    container path to the same storage account (or the other way round)."""
    public = (
        AZ_VM % "false"
        + """
resource "azurerm_storage_container" "public" {
  name                  = "public"
  storage_account_name  = azurerm_storage_account.data.name
  container_access_type = "blob"
}
"""
    )
    write(tmp_path, "main.tf", public)
    found = routes(tmp_path, Config())
    assert ["internet", "azure:storage_account:goatdata"] in found
    assert any(r[1] == "azure:virtual_machine:dev-vm" for r in found)
