"""MCP configs in a repository: what a developer's assistant will run."""

import json
from pathlib import Path

import pytest

from breachgraph.cicd.mcp import mcp_configs


def scan(root: Path, servers: dict, name: str = ".mcp.json") -> list[str]:  # type: ignore[type-arg]
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(json.dumps({"mcpServers": servers}, indent=2), encoding="utf-8")
    return [f.rule_id for f in mcp_configs(root, [])]


UNPINNED = "supply-chain/mcp-unpinned-server"


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "some-server"]),
        ("npx", ["-y", "@acme/server"]),
        ("npx", ["-y", "@acme/server@latest"]),
        ("uvx", ["some-server"]),
        ("uvx", ["--from", "some-server", "run-it"]),
    ],
)
def test_a_version_that_can_change_is_flagged(tmp_path: Path, command: str, args: list[str]) -> None:
    assert scan(tmp_path, {"s": {"command": command, "args": args}}) == [UNPINNED]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "some-server@1.2.3"]),
        ("npx", ["-y", "@acme/server@1.2.3"]),
        ("uvx", ["some-server==1.2.3"]),
        ("node", ["server.js"]),
        ("npx", ["./local-server"]),
    ],
)
def test_a_pinned_or_local_server_is_not(tmp_path: Path, command: str, args: list[str]) -> None:
    assert scan(tmp_path, {"s": {"command": command, "args": args}}) == []


def test_plain_http_to_somewhere_else_is_flagged(tmp_path: Path) -> None:
    assert scan(tmp_path, {"s": {"url": "http://mcp.example.com/sse"}}) == ["supply-chain/mcp-plain-http"]


def test_https_and_localhost_are_fine(tmp_path: Path) -> None:
    assert (
        scan(tmp_path, {"a": {"url": "https://mcp.example.com"}, "b": {"url": "http://localhost:3000"}}) == []
    )


def test_the_finding_points_at_the_server(tmp_path: Path) -> None:
    scan(tmp_path, {"first": {"command": "node"}, "second": {"command": "npx", "args": ["x"]}})
    assert mcp_configs(tmp_path, [])[0].location.start_line == 6


def test_an_example_is_not_a_config_anyone_runs(tmp_path: Path) -> None:
    assert scan(tmp_path, {"s": {"command": "npx", "args": ["x"]}}, "examples/.mcp.json") == []


def test_the_vscode_form_and_a_broken_file(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{"servers": {"s": {"command": "npx", "args": ["x"]}}}', encoding="utf-8"
    )
    assert len(mcp_configs(tmp_path, [])) == 1
    (tmp_path / "mcp.json").write_text("{broken", encoding="utf-8")
    assert mcp_configs(tmp_path, []) == []
