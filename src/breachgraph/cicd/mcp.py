"""MCP server configs committed to a repository: code an AI assistant runs on a developer's machine.

`npx -y some-package` with no version runs whatever was published last, every time the assistant
starts, with that developer's access. It's a supply-chain entry point that no lock file covers.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from breachgraph.graph.model import not_run
from breachgraph.models import Category, Confidence, Finding, Location, Severity
from breachgraph.paths import iter_files

TOOL = "cicd"
_CONFIGS = re.compile(r"(?:^|/)(?:\.mcp\.json|mcp\.json|claude_desktop_config\.json)$")
_RUNNERS = {"npx", "pnpx", "bunx", "uvx", "pipx"}
_LOCAL = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::|/|$)")
_REFERENCES = ["https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"]


def _package(args: list[str]) -> str:
    """The package a runner starts: its first argument that isn't a flag or a flag's value."""
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in ("--from", "--spec", "-p", "--package"):
            return args[args.index(arg) + 1] if args.index(arg) + 1 < len(args) else ""
        elif arg == "run":
            continue
        elif arg.startswith("-"):
            skip = arg in ("--index-url", "--registry")
        else:
            return arg
    return ""


def _pinned(package: str) -> bool:
    name = package.lstrip("@")
    version = name.split("@", 1)[1] if "@" in name else ""
    return "==" in package or bool(re.match(r"\d", version))


def _line(text: str, name: str) -> int:
    return next((i for i, ln in enumerate(text.splitlines(), 1) if f'"{name}"' in ln), 1)


def _finding(rel: str, line: int, rule: str, title: str, description: str, fix: str, snippet: str) -> Finding:
    return Finding(
        tool=TOOL,
        rule_id=rule,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        category=Category.CICD,
        confidence=Confidence.HIGH,
        location=Location(path=rel, start_line=line, end_line=line, snippet=snippet[:200]),
        cwe=["CWE-829"],
        remediation=fix,
        references=_REFERENCES,
    )


def _server(rel: str, text: str, name: str, spec: dict[str, Any]) -> list[Finding]:
    command = str(spec.get("command") or "").rsplit("/", 1)[-1]
    args = [str(a) for a in spec.get("args") or []]
    line = _line(text, name)
    out: list[Finding] = []
    if command in _RUNNERS:
        package = _package(args)
        if package and not package.startswith(("/", ".")) and not _pinned(package):
            out.append(
                _finding(
                    rel,
                    line,
                    "supply-chain/mcp-unpinned-server",
                    f"MCP server {name} runs an unpinned package",
                    f"`{command} {package}` runs the latest published version every time an assistant "
                    "starts, with the access of whoever is running it. A compromised release reaches "
                    "every developer who uses this repository.",
                    f"Pin the version, such as `{package}@1.2.3`, and update it deliberately.",
                    f"{command} {' '.join(args)}",
                )
            )
    url = str(spec.get("url") or "")
    if url.startswith("http://") and not _LOCAL.match(url):
        out.append(
            _finding(
                rel,
                line,
                "supply-chain/mcp-plain-http",
                f"MCP server {name} is reached over plain HTTP",
                "Anyone on the network path can read the assistant's traffic or change what the server "
                "tells it to do.",
                "Use https.",
                url,
            )
        )
    return out


def mcp_configs(target: Path, exclude: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for path, rel in iter_files(target, exclude):
        if not _CONFIGS.search(rel) or not_run(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            doc = json.loads(text)
        except (OSError, ValueError):
            continue
        servers = (doc.get("mcpServers") or doc.get("servers") or {}) if isinstance(doc, dict) else {}
        for name, spec in servers.items() if isinstance(servers, dict) else []:
            if isinstance(spec, dict):
                out += _server(rel, text, str(name), spec)
    return out
