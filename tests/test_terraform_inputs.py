"""`var.x` and `local.y`: resolved as far as the repository says, and left alone past that."""

from pathlib import Path

from breachgraph.graph.model import Graph
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.terraform import TerraformSource
from breachgraph.graph.sources.tfvalues import substitute

ROLE = """
resource "aws_iam_role" "app" {
  name = var.role_name
  assume_role_policy = "{}"
}
resource "aws_s3_bucket" "data" {
  bucket = "${local.prefix}-data"
}
resource "aws_iam_role_policy" "p" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::${local.prefix}-data/*" }]
  })
}
"""


def write(root: Path, name: str, text: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")


def load(root: Path) -> tuple[Graph, list[str]]:
    g = Graph()
    ctx = SourceContext(root=root, exclude=[])
    TerraformSource().collect(ctx, g)
    return g, ctx.skipped


def test_substitute_keeps_a_whole_values_type() -> None:
    env = {"var.ports": [80, 443], "var.name": "shop"}
    assert substitute("${var.ports}", env) == [80, 443]
    assert substitute("${var.name}-api", env) == "shop-api"


def test_what_it_cannot_evaluate_stays_as_it_was() -> None:
    assert substitute("${var.missing}", {}) == "${var.missing}"
    assert substitute('${format("%s", var.x)}', {"var.x": "a"}) == '${format("%s", var.x)}'


def test_a_default_names_the_role_and_a_local_names_the_bucket(tmp_path: Path) -> None:
    variables = 'variable "role_name" {\n  default = "web"\n}\nlocals {\n  prefix = "shop"\n}\n'
    write(tmp_path, "main.tf", variables + ROLE)
    g, _ = load(tmp_path)
    assert "aws:iam_role:web" in g.nodes
    bucket = next(n for n in g.nodes.values() if n.attrs.get("arn_name") == "shop-data")
    assert any(e.src == "aws:iam_role:web" and e.dst == bucket.id for e in g.edges)


def test_tfvars_beat_a_default(tmp_path: Path) -> None:
    write(
        tmp_path,
        "main.tf",
        'variable "role_name" {\n  default = "web"\n}\nlocals {\n  prefix = "s"\n}\n' + ROLE,
    )
    write(tmp_path, "terraform.tfvars", 'role_name = "prod"\n')
    assert "aws:iam_role:prod" in load(tmp_path)[0].nodes


def test_a_local_can_name_a_variable(tmp_path: Path) -> None:
    head = 'variable "env" {\n  default = "prod"\n}\nvariable "role_name" {\n  default = "r"\n}\n'
    write(tmp_path, "main.tf", head + 'locals {\n  prefix = "${var.env}-shop"\n}\n' + ROLE)
    assert any(n.attrs.get("arn_name") == "prod-shop-data" for n in load(tmp_path)[0].nodes.values())


def test_a_local_module_gets_what_its_caller_passes(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", 'module "app" {\n  source = "./app"\n  role_name = "called"\n}\n')
    head = 'variable "role_name" {}\nlocals {\n  prefix = "s"\n}\n'
    write(tmp_path, "app/main.tf", head + ROLE)
    assert "aws:iam_role:called" in load(tmp_path)[0].nodes


def test_a_remote_module_is_a_blind_spot(tmp_path: Path) -> None:
    write(tmp_path, "main.tf", 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n')
    assert any("module vpc comes from" in s for s in load(tmp_path)[1])
