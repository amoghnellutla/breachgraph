"""From an outsider's job to production: through the default branch, or through the registry."""

from pathlib import Path

from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.model import Confidence, EdgeKind, Evidence, Graph, Weakness, WeaknessClass
from breachgraph.graph.paths import find_paths
from breachgraph.graph.sources.actions import BRANCH_ID, ActionsSource
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.kubernetes import KubernetesSource

ENTRY = """
name: Triage
on: pull_request_target
permissions:
  {scope}: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
DEPLOY = """
name: Deploy
on:
  push:
    branches: [{branch}]
jobs:
  {job}:
    runs-on: ubuntu-latest
    {environment}
    steps:
      - run: ./deploy.sh
        env:
          PROD_KEY: ${{{{ secrets.PROD_KEY }}}}
"""
PUBLISH = """
name: Publish
on:
  push:
    branches: [main]
env:
  IMAGE: ghcr.io/acme/shop
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: ${{ env.IMAGE }}:latest
"""
POD = """
apiVersion: apps/v1
kind: Deployment
metadata: {{name: shop, namespace: default}}
spec:
  selector: {{matchLabels: {{app: shop}}}}
  template:
    metadata: {{labels: {{app: shop}}}}
    spec:
      containers:
        - name: shop
          image: {image}
          env:
            - name: TOKEN
              valueFrom: {{secretKeyRef: {{name: prod-db, key: token}}}}
"""
JOB = "gha:job:.github/workflows/entry.yml:triage"


def load(root: Path, **files: str) -> tuple[Graph, ActionsSource]:
    flows = root / ".github" / "workflows"
    flows.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (flows / f"{name}.yml").write_text(text, encoding="utf-8")
    g = Graph()
    ctx = SourceContext(root=root, exclude=[])
    KubernetesSource().collect(ctx, g)
    actions = ActionsSource()
    actions.collect(ctx, g)
    actions.delivery(g)
    return g, actions


def deploy(branch: str = "main", job: str = "deploy", environment: str = "") -> str:
    env = f"environment: {environment}" if environment else ""
    return DEPLOY.format(branch=branch, job=job, environment=env)


def edge(g: Graph, src: str, dst: str):  # type: ignore[no-untyped-def]
    return next((e for e in g.edges if e.src == src and e.dst == dst), None)


def weapon(g: Graph) -> None:
    g.nodes[JOB].weaknesses.append(
        Weakness(
            cls=WeaknessClass.CODE_EXECUTION,
            fingerprint="injection",
            title="script injection",
            evidence=Evidence(path=".github/workflows/entry.yml", line=9),
        )
    )


def test_a_write_token_reaches_what_a_deploy_job_holds(tmp_path: Path) -> None:
    g, _ = load(tmp_path, entry=ENTRY.format(scope="contents"), ship=deploy())
    step = edge(g, JOB, BRANCH_ID)
    assert step and step.requires and step.confidence is Confidence.MEDIUM
    weapon(g)
    # A second path for the same weapon: the one to the token doesn't hide it.
    assert {p.target.id for p in find_paths(g)} == {"gha:token:contents", "gha:secret:PROD_KEY"}
    assert BRANCH_ID in next(p for p in find_paths(g) if p.target.id == "gha:secret:PROD_KEY").nodes


def test_no_weapon_no_path(tmp_path: Path) -> None:
    g, _ = load(tmp_path, entry=ENTRY.format(scope="contents"), ship=deploy())
    assert find_paths(g) == []


def test_a_job_that_only_reads_cannot_change_the_branch(tmp_path: Path) -> None:
    g, _ = load(tmp_path, entry=ENTRY.format(scope="issues"), ship=deploy())
    assert BRANCH_ID not in g.nodes


def test_a_push_to_another_branch_is_not_production(tmp_path: Path) -> None:
    g, _ = load(tmp_path, entry=ENTRY.format(scope="contents"), ship=deploy(branch="staging"))
    assert BRANCH_ID not in g.nodes


def test_a_job_that_does_not_deploy_is_not_production(tmp_path: Path) -> None:
    flow = deploy(job="coverage").replace("name: Deploy", "name: Checks")
    g, _ = load(tmp_path, entry=ENTRY.format(scope="contents"), checks=flow)
    assert BRANCH_ID not in g.nodes


def test_an_environment_can_require_a_reviewer_so_it_only_leads(tmp_path: Path) -> None:
    flow = deploy(job="ship", environment="production")
    g, _ = load(tmp_path, entry=ENTRY.format(scope="contents"), ship=flow)
    weapon(g)
    assert next(p for p in find_paths(g) if BRANCH_ID in p.nodes).confidence is Confidence.LOW


def test_a_package_token_replaces_an_image_and_inherits_its_workload(tmp_path: Path) -> None:
    (tmp_path / "k8s.yaml").write_text(POD.format(image="ghcr.io/acme/shop:latest"), encoding="utf-8")
    g, _ = load(tmp_path, entry=ENTRY.format(scope="packages"), publish=PUBLISH)
    image = "image:ghcr.io/acme/shop:latest"
    step = edge(g, JOB, image)
    assert step and step.requires and step.kind is EdgeKind.COMPROMISES
    inherited = [e for e in g.edges if e.src == image]
    assert inherited and not any(e.requires for e in inherited)


def test_a_digest_cannot_be_replaced(tmp_path: Path) -> None:
    pinned = "ghcr.io/acme/shop:1@sha256:" + "a" * 64
    (tmp_path / "k8s.yaml").write_text(POD.format(image=pinned), encoding="utf-8")
    g, _ = load(tmp_path, entry=ENTRY.format(scope="packages"), publish=PUBLISH)
    assert not [e for e in g.edges if e.src == JOB and e.dst.startswith("image:")]


def test_an_image_from_someone_else_is_not_replaceable(tmp_path: Path) -> None:
    (tmp_path / "k8s.yaml").write_text(POD.format(image="ghcr.io/other/shop:latest"), encoding="utf-8")
    g, _ = load(tmp_path, entry=ENTRY.format(scope="packages"), publish=PUBLISH)
    assert not [e for e in g.edges if e.src == JOB and e.dst.startswith("image:")]


def test_the_repository_name_stands_in_outside_actions(tmp_path: Path) -> None:
    root = tmp_path / "shop"
    root.mkdir()
    published = PUBLISH.replace("ghcr.io/acme/shop", "ghcr.io/${{ github.repository }}")
    (root / "k8s.yaml").write_text(POD.format(image="ghcr.io/acme/shop:v1"), encoding="utf-8")
    g, _ = load(root, entry=ENTRY.format(scope="packages"), publish=published)
    assert edge(g, JOB, "image:ghcr.io/acme/shop:v1")


def test_a_full_build_runs_delivery(tmp_path: Path) -> None:
    flows = tmp_path / ".github" / "workflows"
    flows.mkdir(parents=True)
    (flows / "entry.yml").write_text(ENTRY.format(scope="contents"), encoding="utf-8")
    (flows / "ship.yml").write_text(deploy(), encoding="utf-8")
    assert BRANCH_ID in build_attack_graph(tmp_path, [], Config()).graph.nodes
