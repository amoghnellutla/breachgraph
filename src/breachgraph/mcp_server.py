"""`breachgraph mcp`: attack-path answers for AI coding assistants, over MCP on stdin and stdout.

An assistant that wrote a change can ask whether it opened a way in before anyone reviews it. Only
the small part of the protocol a tool server needs is here, so it adds no dependency. It reads the
repository it was started in, and it changes nothing except its cached base report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from breachgraph import __version__
from breachgraph.check import base_path, run_check
from breachgraph.config import Config
from breachgraph.graph import build_attack_graph
from breachgraph.graph.query import answer
from breachgraph.graph.why import explain
from breachgraph.models import ScanResult
from breachgraph.paths import normalize_path
from breachgraph.settings_fix import previews

PROTOCOL = "2025-06-18"
TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_change",
        "description": (
            "Does the current working tree open a new attack path compared with the saved base? Call this "
            "after changing code, infrastructure or CI, before opening a pull request. The first call "
            "saves the base. Set update_base after a change is accepted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "update_base": {"type": "boolean", "description": "Save this tree as the new base."}
            },
        },
    },
    {
        "name": "explain_finding",
        "description": "Why a finding is, or isn't, on an attack path, and which step decides it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "path/to/file or path/to/file:line"}
            },
            "required": ["location"],
        },
    },
    {
        "name": "preview_fixes",
        "description": (
            "Settings changes that remove attack paths, each proved by rebuilding the graph with the "
            "change applied. Returns the diff and how many paths it removes. Changes no files."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "what_reaches",
        "description": (
            "What falls if a secret, role or workload is lost, and what can reach an asset. Give "
            "'lost', 'asset' or both, as part of a name from the attack graph."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "lost": {"type": "string", "description": "A secret, role or workload that leaked."},
                "asset": {"type": "string", "description": "An asset to protect."},
            },
        },
    },
]


def _base(target: Path) -> ScanResult:
    path = base_path(target)
    if not path.is_file():
        raise ValueError("no base yet: call check_change first")
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))


def _explain(target: Path, config: Config, location: str) -> dict[str, Any]:
    result = _base(target)
    file, _, line = location.partition(":")
    found = [
        f
        for f in result.findings
        if f.location.path == normalize_path(file) and (not line or str(f.location.start_line) == line)
    ]
    ag = build_attack_graph(target, result.findings, config)
    return {"findings": [{"title": f.title, "why": explain(f, ag)} for f in found]}


def _what_reaches(target: Path, config: Config, lost: str | None, asset: str | None) -> dict[str, Any]:
    if not lost and not asset:
        raise ValueError("give 'lost', 'asset' or both")
    graph = build_attack_graph(target, _base(target).findings, config).graph
    return answer(graph, lost, asset, config.attack_graph.crown_value)


def handle(message: dict[str, Any], target: Path, config: Config) -> dict[str, Any] | None:
    """The response to one JSON-RPC message; None for a notification."""
    method, ident = message.get("method"), message.get("id")
    if ident is None:
        return None
    reply: dict[str, Any] = {"jsonrpc": "2.0", "id": ident}
    if method == "initialize":
        reply["result"] = {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "breachgraph", "version": __version__},
        }
    elif method == "ping":
        reply["result"] = {}
    elif method == "tools/list":
        reply["result"] = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        try:
            if name == "check_change":
                out = run_check(target, config, bool(args.get("update_base")))
            elif name == "explain_finding":
                out = _explain(target, config, str(args["location"]))
            elif name == "preview_fixes":
                out = {"fixes": previews(_base(target), target, config)}
            elif name == "what_reaches":
                out = _what_reaches(target, config, args.get("lost"), args.get("asset"))
            else:
                reply["error"] = {"code": -32602, "message": f"unknown tool: {name}"}
                return reply
            reply["result"] = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]}
        except Exception as exc:  # the assistant should see the reason, and the server stays up
            reply["result"] = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    else:
        reply["error"] = {"code": -32601, "message": f"unknown method: {method}"}
    return reply


def serve(target: Path, config: Config, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    for line in stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        response = handle(message, target, config)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
