"""A credential in the repository matters for what it opens, and only when it can open it."""

from pathlib import Path

import pytest

from breachgraph.graph.correlate import attach
from breachgraph.graph.model import Confidence, Graph, Node, NodeKind, WeaknessClass
from breachgraph.graph.paths import find_paths
from breachgraph.graph.sources.app import READER_ID, committed_databases
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.routes import Route
from tests.conftest import make_finding

PASSWORD = "kT9vQ2mXw7Lp"


def scan(root: Path, name: str, text: str) -> Graph:
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")
    g = Graph()
    committed_databases(SourceContext(root=root, exclude=[]), g)
    return g


def test_a_real_password_for_a_hosted_database_is_a_path(tmp_path: Path) -> None:
    url = f"postgres://app:{PASSWORD}@db.abc.us-east-1.rds.amazonaws.com:5432/shop"
    paths = find_paths(scan(tmp_path, ".env", f"DATABASE_URL={url}\n"))
    assert [p.confidence for p in paths] == [Confidence.MEDIUM]
    assert paths[0].nodes[1] == READER_ID
    assert PASSWORD not in paths[0].target.name + str(paths[0].steps[-1].weakness_title)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".env", f"DATABASE_URL=postgres://app:{PASSWORD}@localhost:5432/shop"),  # a laptop
        (".env", f"DATABASE_URL=postgres://app:{PASSWORD}@db:5432/shop"),  # a private name
        (".env", "DATABASE_URL=postgres://app:${DB_PASSWORD}@x.rds.amazonaws.com/shop"),
        (".env", "DATABASE_URL=postgres://app:changeme@x.rds.amazonaws.com/shop"),
        (".env", "DATABASE_URL=postgres://app:<password>@x.neon.tech/shop"),
        (".env.example", f"DATABASE_URL=postgres://app:{PASSWORD}@x.neon.tech/shop"),
        ("tests/.env", f"DATABASE_URL=postgres://app:{PASSWORD}@x.neon.tech/shop"),
        ("README.md", f"postgres://app:{PASSWORD}@x.neon.tech/shop"),
    ],
)
def test_what_does_not_count(tmp_path: Path, name: str, text: str) -> None:
    assert not scan(tmp_path, name, text).nodes


def route_graph(guard: str) -> tuple[Graph, list[Route]]:
    g = Graph()
    g.add_node(Node(id="w", kind=NodeKind.WORKLOAD, name="w"))
    r = Route(
        method="GET", path="/admin", file="app.py", start_line=1, end_line=2, framework="flask",
        handler="admin", auth=guard,
    )  # fmt: skip
    return g, [r]


def key(path: str = "app.py"):  # type: ignore[no-untyped-def]
    f = make_finding(path=path, rule_id="breachgraph.python.hardcoded-signing-key")
    f.cwe = ["CWE-321"]
    return f


def route_node(g: Graph) -> Node:
    return next(n for n in g.nodes.values() if n.kind is NodeKind.ROUTE)


def test_a_signing_key_lifts_the_login_from_a_guarded_route(tmp_path: Path) -> None:
    g, routes = route_graph("login_required")
    attach(g, [key()], routes, [])
    assert route_node(g).has({WeaknessClass.AUTH_BYPASS})


def test_an_open_route_has_no_login_to_lift(tmp_path: Path) -> None:
    g, routes = route_graph("")
    attach(g, [key()], routes, [])
    assert not route_node(g).has({WeaknessClass.AUTH_BYPASS})


def test_a_key_in_a_test_lifts_nothing(tmp_path: Path) -> None:
    g, routes = route_graph("login_required")
    attach(g, [key("tests/test_auth.py")], routes, [])
    assert not route_node(g).has({WeaknessClass.AUTH_BYPASS})
