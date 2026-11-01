"""False paths found by hand review of real projects: each stays reported but doesn't gate."""

from pathlib import Path

import pytest

from breachgraph.cicd import analyze
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import Confidence
from breachgraph.models import Category, Severity
from tests.test_callgraph import JEWEL, cmd_injection
from tests.test_entry_points import write

SAME_REPO = """on:
  workflow_run:
    workflows: [test]
    types: [completed]
jobs:
  publish:
    if: github.event.workflow_run.head_repository.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.DOCKER_PASSWORD }}
"""
TRUSTED_UPSTREAM = """name: deploy
on: workflow_dispatch
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
FOLLOWS = """on:
  workflow_run:
    workflows: [deploy]
jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.KEY }}
"""


def jobs(root: Path) -> list[str]:
    return [n for n in build_attack_graph(root, [], Config()).graph.nodes if n.startswith("gha:job:")]


def test_a_same_repository_guard_keeps_a_job_out_of_the_graph(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/p.yml", SAME_REPO)
    assert jobs(tmp_path) == []


def test_following_a_trusted_workflow_is_not_an_entry_point(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/d.yml", TRUSTED_UPSTREAM)
    write(tmp_path, ".github/workflows/c.yml", FOLLOWS)
    assert jobs(tmp_path) == []


CHECK_FIRST = """on: issue_comment
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v9
        with:
          script: |
            const { data: perm } = await github.rest.repos.getCollaboratorPermissionLevel({})
      - run: echo ${{ github.event.comment.body }}
"""
CHECK_AFTER = """on: issue_comment
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.comment.body }}
      - uses: actions/github-script@v9
        with:
          script: github.rest.repos.getCollaboratorPermissionLevel({})
"""


def test_a_permission_check_in_an_earlier_step_is_a_gate(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/m.yml", CHECK_FIRST)
    [f] = analyze(tmp_path, [])[0]
    assert f.severity is Severity.MEDIUM and "fails the job unless" in f.description


def test_a_check_after_the_injection_is_no_gate(tmp_path: Path) -> None:
    write(tmp_path, ".github/workflows/m.yml", CHECK_AFTER)
    [f] = analyze(tmp_path, [])[0]
    assert f.severity is Severity.HIGH


def test_a_command_action_is_a_permission_gate(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".github/workflows/c.yml",
        """on: issue_comment
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: github/command@v2
        with:
          permissions: "write,admin"
  build:
    needs: check
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.comment.body }}
""",
    )
    [f] = analyze(tmp_path, [])[0]
    assert f.severity is Severity.MEDIUM


@pytest.mark.parametrize(
    ("file", "header", "expected"),
    [
        ("docker-compose.yml", "name: shop-dev\n", Confidence.LOW),
        ("docker-compose.dev.yml", "", Confidence.MEDIUM),  # not one of the compose file names read
        ("deploy/docker-compose.yml", "", Confidence.MEDIUM),
        ("dev/docker-compose.yml", "", Confidence.LOW),
    ],
)
def test_a_developer_compose_project(tmp_path: Path, file: str, header: str, expected: Confidence) -> None:
    write(tmp_path, file, header + "services:\n  web:\n    build: .\n    ports: ['80:80']\n")
    edges = [e for e in build_attack_graph(tmp_path, [], Config()).graph.edges if e.src == "internet"]
    if "compose.dev" in file:
        assert not edges
    else:
        assert [e.confidence for e in edges] == [expected]


def test_a_bucket_named_public_does_not_gate(tmp_path: Path) -> None:
    write(
        tmp_path,
        "main.tf",
        'resource "aws_s3_bucket" "a" {\n  bucket = "shop-public-assets"\n  acl = "public-read"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "shop-customer-data"\n  acl = "public-read"\n}\n',
    )
    res = build_attack_graph(tmp_path, [], Config())
    by_name = {p.target.name: p.confidence for p in res.paths}
    assert by_name["S3 bucket shop-customer-data"] is Confidence.MEDIUM
    assert by_name.get("S3 bucket shop-public-assets", Confidence.LOW) is Confidence.LOW


def test_a_dependency_on_the_whole_repository_stand_in_does_not_gate(tmp_path: Path) -> None:
    write(
        tmp_path,
        "app.py",
        'import psycopg2\nfrom flask import Flask\napp = Flask(__name__)\n\n@app.get("/x")\ndef x():\n    pass\n',
    )
    f = cmd_injection("requirements.txt", 1)
    f.category = Category.SCA
    f.enrichment.kev = True
    res = build_attack_graph(tmp_path, [f], JEWEL)
    weak = [w for n in res.graph.nodes.values() for w in n.weaknesses]
    assert weak and all(w.confidence is Confidence.LOW for w in weak)
