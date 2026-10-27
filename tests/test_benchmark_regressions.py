"""Bugs found by running breachgraph on real vulnerable-by-design projects (benchmarks/).

Each test is a minimal fixture distilled from the project that exposed the bug.
"""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import INTERNET_ID, EdgeKind, Graph, NodeKind
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.terraform import TerraformSource
from tests.test_graph_paths import finding


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def tf(root: Path) -> tuple[Graph, list[str]]:
    g = Graph()
    ctx = SourceContext(root=root, exclude=[])
    TerraformSource().collect(ctx, g)
    return g, ctx.skipped


def has(g: Graph, src: str, dst: str, kind: EdgeKind | None = None) -> bool:
    return any(e.src == src and e.dst == dst and (kind is None or e.kind is kind) for e in g.edges)


def test_heredoc_terminator_with_trailing_space(tmp_path: Path) -> None:
    """AzureGoat: `EOF ` made python-hcl2 swallow the rest of the file without an error."""
    write(
        tmp_path,
        "main.tf",
        'resource "null_resource" "x" {\n  provisioner "local-exec" {\n    command = <<EOF\necho hi\nEOF \n  }\n}\n\n'
        'resource "aws_s3_bucket" "after" {\n  bucket = "after-the-heredoc"\n}\n',
    )
    g, skipped = tf(tmp_path)
    assert "aws:s3_bucket:after-the-heredoc" in g.nodes and not skipped


def test_one_unparseable_block_does_not_hide_the_file(tmp_path: Path) -> None:
    write(
        tmp_path,
        "main.tf",
        'resource "aws_s3_bucket" "good" {\n  bucket = "kept"\n}\n\n'
        'resource "aws_instance" "bad" {\n  ami = "x" "y"\n}\n\n'
        'resource "aws_s3_bucket" "also_good" {\n  bucket = "kept-too"\n}\n',
    )
    g, skipped = tf(tmp_path)
    assert {"aws:s3_bucket:kept", "aws:s3_bucket:kept-too"} <= set(g.nodes)
    assert any("could not parse 1 block(s) (aws_instance.bad)" in s for s in skipped)


AZ_ESCALATION = """
resource "azurerm_storage_account" "data" {
  name                = "goatdata"
  resource_group_name = var.resource_group
}
resource "azurerm_linux_virtual_machine" "dev" {
  name                  = "dev-vm"
  resource_group_name   = var.resource_group
  network_interface_ids = []
  identity {
    type = "SystemAssigned"
  }
}
resource "azurerm_user_assigned_identity" "ops" {
  name                = "ops"
  resource_group_name = var.resource_group
}
resource "azurerm_automation_account" "ops" {
  name                = "ops-automation"
  resource_group_name = var.resource_group
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.ops.id]
  }
}
resource "azurerm_role_assignment" "vm" {
  scope                = "${data.azurerm_subscription.primary.id}/resourceGroups/${var.resource_group}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_linux_virtual_machine.dev.identity.0.principal_id
}
resource "azurerm_role_assignment" "ops" {
  scope                = "${data.azurerm_subscription.primary.id}/resourceGroups/${var.resource_group}"
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.ops.principal_id
}
"""


def test_azure_contributor_escalates_through_compute_in_scope(tmp_path: Path) -> None:
    """AzureGoat: VM identity (Contributor on the group) -> runbook job -> Owner identity."""
    write(tmp_path, "main.tf", AZ_ESCALATION)
    g, skipped = tf(tmp_path)
    vm_id = "azure:linux_virtual_machine:dev-vm/system-identity"
    assert not skipped
    # `.identity.0.principal_id` (HCL 0.11 index syntax) and a group named by a variable resolve.
    assert has(g, vm_id, "azure:storage_account:goatdata", EdgeKind.CAN_ACCESS)
    edge = next(e for e in g.edges if e.src == vm_id and e.dst == "azure:identity:ops")
    assert "Automation account ops-automation" in edge.note and not edge.requires
    assert has(g, "azure:identity:ops", "azure:storage_account:goatdata")  # Owner


def test_legacy_function_app_is_a_workload_with_its_code(tmp_path: Path) -> None:
    """AzureGoat / GCPGoat / AWSGoat: functions deploy zips built by data.archive_file."""
    write(tmp_path, "functions/data/app.py", "def main(req):\n    return 'ok'\n")
    write(
        tmp_path,
        "main.tf",
        """
data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "functions/data"
  output_path = "functions/data/fn.zip"
}
resource "azurerm_storage_blob" "fn" {
  name   = "fn.zip"
  source = "functions/data/fn.zip"
}
resource "azurerm_function_app" "api" {
  name = "goat-api"
  app_settings = {
    WEBSITE_RUN_FROM_PACKAGE = "https://x.blob.core.windows.net/c/${azurerm_storage_blob.fn.name}"
  }
}
resource "aws_lambda_function" "data" {
  function_name = "goat-data"
  filename      = data.archive_file.fn.output_path
  role          = "x"
}
resource "google_storage_bucket_object" "zip" {
  name   = "function.zip"
  source = "functions/data/fn.zip"
}
resource "google_cloudfunctions_function" "backend" {
  name                  = "backend"
  source_archive_object = google_storage_bucket_object.zip.name
}
""",
    )
    g, _ = tf(tmp_path)
    for nid in ("azure:function_app:goat-api", "aws:lambda:goat-data", "gcp:cloudfunctions_function:backend"):
        assert g.nodes[nid].kind is NodeKind.WORKLOAD
        assert g.nodes[nid].attrs["code_paths"] == ["functions/data"], nid
    assert has(g, INTERNET_ID, "azure:function_app:goat-api", EdgeKind.EXPOSES)


def test_code_finding_in_function_source_reaches_its_identity(tmp_path: Path) -> None:
    """End to end: a code-execution finding in deployed function code unlocks the function's role."""
    write(
        tmp_path,
        "src/handler.py",
        "import os\n\ndef handler(event, ctx):\n    return os.popen(event['q']).read()\n",
    )
    write(
        tmp_path,
        "infra/main.tf",
        """
data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/fn.zip"
}
resource "aws_s3_bucket" "pii" {
  bucket = "customer-pii"
}
resource "aws_iam_role" "fn" {
  name               = "fn-role"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
}
resource "aws_lambda_function" "fn" {
  function_name = "query"
  filename      = data.archive_file.fn.output_path
  role          = aws_iam_role.fn.arn
}
resource "aws_lambda_function_url" "fn" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "NONE"
}
""",
    )
    cmdi = finding("src/handler.py", 4, "CWE-78", "Command injection", "cmdi-fn")
    res = build_attack_graph(tmp_path, [cmdi], Config())
    routes = [p.nodes for p in res.paths if p.target.id == "aws:s3_bucket:customer-pii"]
    assert ["internet", "aws:lambda:query", "aws:iam_role:fn-role", "aws:s3_bucket:customer-pii"] in routes
    assert not any(
        p.target.id == "aws:s3_bucket:customer-pii" for p in build_attack_graph(tmp_path, [], Config()).paths
    )


def test_container_escape_reaches_a_crown_jewel(tmp_path: Path) -> None:
    """Kubernetes Goat: root on the worker node had value 0, so escape paths had no target."""
    write(
        tmp_path,
        "k8s.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: health-check, namespace: default}
spec:
  template:
    spec:
      containers:
        - name: app
          image: goat/health-check:1
          securityContext: {privileged: true}
""",
    )
    g = Graph()
    from breachgraph.graph.sources.kubernetes import KubernetesSource

    KubernetesSource().collect(SourceContext(root=tmp_path, exclude=[]), g)
    host = g.nodes["k8s:host:nodes"]
    assert host.value >= Config().attack_graph.crown_value


ROLE_WITH_FILE_POLICY = """
resource "aws_s3_bucket" "secrets" {
  bucket = "cg-secrets"
}
resource "aws_iam_role" "app" {
  name               = "cg-app"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_policy" "read" {
  name   = "read"
  policy = file("policies/read.json")
}
resource "aws_iam_role_policy_attachment" "read" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.read.arn
}
"""


def test_policy_kept_in_a_file(tmp_path: Path) -> None:
    """CloudGoat: policy = file("policies/v1.json") was a blind spot."""
    write(tmp_path, "infra/main.tf", ROLE_WITH_FILE_POLICY)
    write(
        tmp_path,
        "infra/policies/read.json",
        '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::cg-secrets/*"}]}',
    )
    g, skipped = tf(tmp_path)
    assert has(g, "aws:iam_role:cg-app", "aws:s3_bucket:cg-secrets", EdgeKind.CAN_ACCESS) and not skipped


def test_jsonencode_with_function_calls_and_reference_lists() -> None:
    """CloudGoat: concat(...) in a condition, and `[aws_x.y.arn, ...]` lists, broke decoding."""
    from breachgraph.graph.sources.hcl import decode_policy

    doc = decode_policy(
        '${jsonencode({ Statement = [{ Effect = "Allow", Resource = [aws_s3_bucket.b.arn, "x"], '
        'Condition = { IpAddress = { "aws:SourceIp" = concat(var.ips, ["1.2.3.4/32"]) } } }] })}'
    )
    assert doc is not None
    st = doc["Statement"][0]
    assert st["Resource"] == ["${aws_s3_bucket.b.arn}", "x"]
    assert st["Condition"]["IpAddress"]["aws:SourceIp"].startswith("${concat(")


APIGW_LAMBDA = """
data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "src"
  output_path = "fn.zip"
}
resource "aws_dynamodb_table" "posts" {
  name = "blog-posts"
}
resource "aws_iam_role" "fn" {
  name               = "fn-role"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess"]
}
resource "aws_lambda_function" "data" {
  function_name = "blog-data"
  filename      = data.archive_file.fn.output_path
  role          = aws_iam_role.fn.arn
}
resource "aws_api_gateway_method" "get" {
  http_method   = "GET"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "get" {
  http_method = aws_api_gateway_method.get.http_method
  type        = "AWS_PROXY"
  uri         = aws_lambda_function.data.invoke_arn
}
"""


def test_rest_api_gateway_exposes_lambda_and_nosql_injection_reads_dynamodb(tmp_path: Path) -> None:
    """AWSGoat: REST API Gateway (v1) integrations weren't exposure, and NoSQL injection in a
    handler (no framework route) never reached the DynamoDB table its role can read."""
    write(
        tmp_path,
        "src/handler.py",
        "def handler(event, ctx):\n    return table.scan(FilterExpression=event['q'])\n",
    )
    write(tmp_path, "main.tf", APIGW_LAMBDA)
    nosqli = finding("src/handler.py", 2, "CWE-943", "NoSQL injection", "nosqli")
    res = build_attack_graph(tmp_path, [nosqli], Config())
    assert ["internet", "aws:lambda:blog-data", "aws:dynamodb_table:blog-posts"] in [
        p.nodes for p in res.paths
    ]
    exposure = next(e for e in res.graph.edges if e.src == INTERNET_ID and e.dst == "aws:lambda:blog-data")
    assert "authorization NONE" in exposure.note
    assert not any(
        p.target.id == "aws:dynamodb_table:blog-posts"
        for p in build_attack_graph(tmp_path, [], Config()).paths
    )
