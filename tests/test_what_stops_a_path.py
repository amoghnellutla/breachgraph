"""A control that holds removes the path. Each of these once reported one that doesn't exist."""

from pathlib import Path

import pytest

from breachgraph.graph.model import INTERNET_ID, Confidence, Graph
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.terraform import TerraformSource

SG = """
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
VPC = """
resource "aws_internet_gateway" "gw" { vpc_id = "v" }
resource "aws_nat_gateway" "nat" { subnet_id = "x" }
resource "aws_route_table" "out" {
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}
resource "aws_route_table" "inside" {
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}
resource "aws_subnet" "front" { map_public_ip_on_launch = true }
resource "aws_subnet" "back" { map_public_ip_on_launch = false }
resource "aws_subnet" "front_quiet" { map_public_ip_on_launch = false }
resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.front.id
  route_table_id = aws_route_table.out.id
}
resource "aws_route_table_association" "c" {
  subnet_id = aws_subnet.front_quiet.id
  route_table_id = aws_route_table.out.id
}
resource "aws_route_table_association" "b" {
  subnet_id = aws_subnet.back.id
  route_table_id = aws_route_table.inside.id
}
"""


def instance(subnet: str, extra: str = "") -> str:
    return f"""
resource "aws_instance" "box" {{
  ami = "a"
  subnet_id = {subnet}
  vpc_security_group_ids = [aws_security_group.web.id]
  {extra}
}}
"""


def load(tmp: Path, text: str) -> Graph:
    (tmp / "main.tf").write_text(text, encoding="utf-8")
    g = Graph()
    TerraformSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def exposed(g: Graph):  # type: ignore[no-untyped-def]
    return next((e for e in g.edges if e.src == INTERNET_ID and e.dst.startswith("aws:ec2")), None)


def test_a_public_subnet_is_exposed(tmp_path: Path) -> None:
    edge = exposed(load(tmp_path, SG + VPC + instance("aws_subnet.front.id")))
    assert edge and edge.confidence is Confidence.HIGH


@pytest.mark.parametrize(
    ("subnet", "extra"),
    [
        ("aws_subnet.back.id", ""),  # a NAT gateway is the only way out
        ("aws_subnet.back.id", "associate_public_ip_address = true"),  # an address with no route
        ("aws_subnet.front_quiet.id", ""),  # a route with no address
        ("aws_subnet.front.id", "associate_public_ip_address = false"),
        ("module.vpc.private_subnets[0]", ""),
    ],
)
def test_no_route_or_no_address_means_no_path(tmp_path: Path, subnet: str, extra: str) -> None:
    assert not exposed(load(tmp_path, SG + VPC + instance(subnet, extra)))


def test_an_unknown_subnet_stays_uncertain(tmp_path: Path) -> None:
    edge = exposed(load(tmp_path, SG + instance("var.subnet_id")))
    assert edge and edge.confidence is Confidence.MEDIUM


ROLE = """
resource "aws_iam_role" "app" {{
  name = "app"
  assume_role_policy = "{{}}"
  {boundary}
}}
resource "aws_iam_role_policy" "p" {{
  role = aws_iam_role.app.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{ Effect = "Allow", Action = {actions}, Resource = "*" }}]
  }})
}}
resource "aws_s3_bucket" "data" {{ bucket = "shop-data" }}
{extra}
"""
CAP = """
resource "aws_iam_policy" "cap" {
  name = "cap"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:ListAllMyBuckets"], Resource = "*" }]
  })
}
"""
SCP = """
resource "aws_organizations_policy" "deny" {
  name = "deny"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = ["s3:*"], Resource = "*" }]
  })
}
"""
ATTACH = """
resource "aws_organizations_policy_attachment" "a" {
  policy_id = aws_organizations_policy.deny.id
  target_id = "111"
}
"""
APP = "aws:iam_role:app"


def role(tmp: Path, actions: str = '["s3:*"]', boundary: str = "", extra: str = "") -> Graph:
    return load(tmp, ROLE.format(actions=actions, boundary=boundary, extra=extra))


def reaches_data(g: Graph) -> bool:
    return any(e.src == APP and e.dst.startswith("aws:s3") for e in g.edges)


def test_without_a_guardrail_the_role_reads_the_bucket(tmp_path: Path) -> None:
    assert reaches_data(role(tmp_path))


def test_a_boundary_caps_what_the_policy_grants(tmp_path: Path) -> None:
    g = role(tmp_path, boundary="permissions_boundary = aws_iam_policy.cap.arn", extra=CAP)
    assert not reaches_data(g)


def test_a_boundary_stops_a_way_to_administrator(tmp_path: Path) -> None:
    g = role(tmp_path, '["iam:AttachRolePolicy"]', "permissions_boundary = aws_iam_policy.cap.arn", CAP)
    assert not any(e.dst == "aws:account-admin" for e in g.edges)


def test_an_unreadable_boundary_says_so(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        ROLE.format(actions='["s3:*"]', boundary="permissions_boundary = var.cap", extra=""), encoding="utf-8"
    )
    ctx = SourceContext(root=tmp_path, exclude=[])
    TerraformSource().collect(ctx, Graph())
    assert any("permissions boundary" in s for s in ctx.skipped)


def test_an_attached_scp_denies_and_a_detached_one_does_not(tmp_path: Path) -> None:
    assert reaches_data(role(tmp_path, extra=SCP))
    assert not reaches_data(role(tmp_path, extra=SCP + ATTACH))


TRUSTS = """
resource "aws_iam_role" "fn" {{
  name = "fn"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{ Effect = "Allow", Action = "sts:AssumeRole", Principal = {{ Service = "{service}" }} }}]
  }})
}}
"""
PASS = '["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]'
FN = "aws:iam_role:fn"


def test_passing_a_role_reaches_one_that_trusts_the_service(tmp_path: Path) -> None:
    g = role(tmp_path, PASS, extra=TRUSTS.format(service="lambda.amazonaws.com"))
    assert any(e.src == APP and e.dst == FN for e in g.edges)
    assert not any(e.dst == "aws:account-admin" for e in g.edges)  # not everything


def test_a_role_that_trusts_another_service_cannot_be_passed_here(tmp_path: Path) -> None:
    g = role(tmp_path, PASS, extra=TRUSTS.format(service="ec2.amazonaws.com"))
    assert not any(e.src == APP and e.dst == FN for e in g.edges)


def test_no_trusting_role_here_is_only_a_lead(tmp_path: Path) -> None:
    edge = next(e for e in role(tmp_path, PASS).edges if e.dst == "aws:account-admin")
    assert edge.confidence is Confidence.LOW


DB = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_security_group" "db" {}
resource "aws_security_group_rule" "in" {
  type = "ingress"
  cidr_blocks = [%s]
  security_group_id = aws_security_group.db.id
}
resource "aws_db_instance" "main" {
  publicly_accessible = true
  password = "committed"
  vpc_security_group_ids = [%s]
}
"""


def reaches_database(tmp_path: Path, cidr: str, groups: str = "aws_security_group.db.id") -> bool:
    graph = load(tmp_path, DB % (cidr, groups))
    return any(e.src == INTERNET_ID and "endpoint" in e.dst for e in graph.edges)


def test_a_public_database_behind_its_own_network_is_not_reachable(tmp_path: Path) -> None:
    assert not reaches_database(tmp_path, "aws_vpc.main.cidr_block")
    assert not reaches_database(tmp_path, '"10.0.0.0/8"')


@pytest.mark.parametrize(
    ("cidr", "groups"),
    [
        ('"0.0.0.0/0"', "aws_security_group.db.id"),
        ("var.allowed", "aws_security_group.db.id"),  # could be anything
        ('"10.0.0.0/8"', '"sg-0123", aws_security_group.db.id'),  # a group we can't read
    ],
)
def test_a_database_stays_reported_unless_every_group_shuts_it(
    tmp_path: Path, cidr: str, groups: str
) -> None:
    assert reaches_database(tmp_path, cidr, groups)
