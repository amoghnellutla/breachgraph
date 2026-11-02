"""Becoming a role by changing what runs as it, and reaching a function by sending it an event."""

from pathlib import Path

import pytest

from breachgraph.graph.model import Confidence, EdgeKind, Graph
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.terraform import ESCALATION_SETS, TerraformSource

ROLES = """
resource "aws_iam_role" "dev" {{
  name = "dev"
  assume_role_policy = "{{}}"
}}
resource "aws_iam_role" "fn" {{
  name = "fn"
  assume_role_policy = "{{}}"
}}
resource "aws_iam_role_policy" "dev" {{
  role = aws_iam_role.dev.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{ Effect = "Allow", Action = {actions}, Resource = "{resource}" }}]
  }})
}}
resource "aws_s3_bucket" "code" {{
  bucket = "shop-code"
}}
resource "aws_lambda_function" "pay" {{
  function_name = "pay"
  role = aws_iam_role.fn.arn
  handler = "a.b"
  runtime = "python3.12"
  s3_bucket = aws_s3_bucket.code.id
  s3_key = "pay.zip"
}}
{extra}
"""
DEV = "aws:iam_role:dev"
FN = "aws:iam_role:fn"
LAMBDA = "aws:lambda:pay"


def load(tmp: Path, actions: str, resource: str = "*", extra: str = "") -> Graph:
    text = ROLES.format(actions=actions, resource=resource, extra=extra)
    (tmp / "main.tf").write_text(text, encoding="utf-8")
    g = Graph()
    TerraformSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def edge(g: Graph, src: str, dst: str):  # type: ignore[no-untyped-def]
    return next((e for e in g.edges if e.src == src and e.dst == dst), None)


def test_updating_function_code_becomes_its_role(tmp_path: Path) -> None:
    step = edge(load(tmp_path, '["lambda:UpdateFunctionCode"]'), DEV, FN)
    assert step and step.kind is EdgeKind.USES_IDENTITY and step.confidence is Confidence.HIGH


def test_only_the_function_named_in_the_policy(tmp_path: Path) -> None:
    arn = "arn:aws:lambda:us-east-1:1:function:other"
    assert not edge(load(tmp_path, '["lambda:UpdateFunctionCode"]', arn), DEV, FN)


def test_reading_a_function_is_not_writing_it(tmp_path: Path) -> None:
    assert not edge(load(tmp_path, '["lambda:GetFunction"]'), DEV, FN)


def test_overwriting_the_code_in_its_bucket_is_a_lead(tmp_path: Path) -> None:
    step = edge(load(tmp_path, '["s3:PutObject"]'), DEV, FN)
    assert step and step.confidence is Confidence.LOW


NOTIFY = """
resource "aws_s3_bucket_notification" "n" {
  bucket = aws_s3_bucket.code.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.pay.arn
    events = ["s3:ObjectCreated:*"]
  }
}
"""


def test_writing_to_a_bucket_reaches_the_function_it_triggers(tmp_path: Path) -> None:
    step = edge(load(tmp_path, '["s3:PutObject"]', extra=NOTIFY), DEV, LAMBDA)
    assert step and step.kind is EdgeKind.EXPOSES and not step.requires


def test_reading_a_bucket_triggers_nothing(tmp_path: Path) -> None:
    assert not edge(load(tmp_path, '["s3:GetObject"]', extra=NOTIFY), DEV, LAMBDA)


def test_the_bucket_that_holds_terraform_state_is_a_crown_jewel(tmp_path: Path) -> None:
    backend = 'terraform {\n  backend "s3" {\n    bucket = "shop-code"\n    key = "tf"\n  }\n}\n'
    g = load(tmp_path, '["s3:GetObject"]', extra=backend)
    bucket = next(n for n in g.nodes.values() if n.attrs.get("arn_name") == "shop-code")
    assert "Terraform state" in bucket.name and bucket.value >= 9


@pytest.mark.parametrize(
    ("actions", "reason"),
    [
        ('["iam:CreateLoginProfile"]', "console password"),
        ('["iam:AddUserToGroup"]', "group"),
    ],
)
def test_more_ways_to_administrator(tmp_path: Path, actions: str, reason: str) -> None:
    assert any(reason in why for _needed, why in ESCALATION_SETS)
    step = edge(load(tmp_path, actions), DEV, "aws:account-admin")
    assert step and reason in step.note


def test_half_a_method_is_no_method(tmp_path: Path) -> None:
    assert not edge(load(tmp_path, '["glue:CreateDevEndpoint"]'), DEV, "aws:account-admin")
