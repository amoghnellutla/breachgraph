"""`breachgraph check` and the MCP server: asked before a pull request, and answered honestly."""

import io
import json
from pathlib import Path

import pytest

from breachgraph import check as check_module
from breachgraph import pipeline
from breachgraph.config import Config
from breachgraph.mcp_server import TOOLS, handle, serve
from tests.test_callgraph import JEWEL, cmd_injection, python_app
from tests.test_incremental import Recorder


@pytest.fixture(autouse=True)
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BREACHGRAPH_CACHE_DIR", str(tmp_path / "cache"))


def repo(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp / "repo"
    python_app(root)
    monkeypatch.setattr(pipeline, "SCANNERS", {"semgrep": Recorder("semgrep", [])})
    return root


def test_first_check_saves_a_base_then_compares(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = repo(tmp_path, monkeypatch)
    assert check_module.run_check(root, JEWEL)["status"] == "baseline"
    assert check_module.run_check(root, JEWEL)["status"] == "clear"
    assert not list(root.rglob("breachgraph*.json"))  # nothing written into the repository


def test_a_change_that_opens_a_path_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = repo(tmp_path, monkeypatch)
    check_module.run_check(root, JEWEL)
    app = root / "api" / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    finding = cmd_injection("api/app.py", 8)
    monkeypatch.setattr(pipeline, "SCANNERS", {"semgrep": Recorder("semgrep", [finding])})
    out = check_module.run_check(root, JEWEL)
    assert out["status"] == "opens" and "GET /run" in out["opens"][0]["route"]
    assert out["opens"][0]["weapons"][0]["at"] == "api/app.py:8"


def test_the_protocol(tmp_path: Path) -> None:
    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, tmp_path, Config())
    assert init and init["result"]["serverInfo"]["name"] == "breachgraph"
    listed = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tmp_path, Config())
    assert listed and [t["name"] for t in listed["result"]["tools"]] == [t["name"] for t in TOOLS]
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, tmp_path, Config()) is None
    missing = handle({"jsonrpc": "2.0", "id": 3, "method": "nope"}, tmp_path, Config())
    assert missing and missing["error"]["code"] == -32601


def test_a_tool_failure_is_an_answer_not_a_crash(tmp_path: Path) -> None:
    call = {"name": "explain_finding", "arguments": {"location": "a.py:1"}}
    res = handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": call}, tmp_path, Config())
    assert res and res["result"]["isError"] and "no base yet" in res["result"]["content"][0]["text"]


def test_the_server_speaks_one_json_message_per_line(tmp_path: Path) -> None:
    out = io.StringIO()
    serve(tmp_path, Config(), io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\nnot json\n\n'), out)
    assert json.loads(out.getvalue()) == {"jsonrpc": "2.0", "id": 1, "result": {}}
