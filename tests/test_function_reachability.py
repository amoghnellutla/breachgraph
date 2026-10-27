"""Function-level reachability for Go, from the Go vulnerability database's symbols (OSV)."""

import json
from pathlib import Path

import httpx

from breachgraph.config import Config
from breachgraph.models import Category, Confidence, Finding, Location, Package, Severity
from breachgraph.reachability import annotate_reachability
from breachgraph.reachability.functions import SymbolDB, _package_name
from breachgraph.scoring import score_all
from tests.test_entry_points import write

GO_RECORD = {
    "id": "GO-2023-1988",
    "aliases": ["CVE-2023-3978"],
    "affected": [
        {
            "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
            "ecosystem_specific": {
                "imports": [{"path": "golang.org/x/net/html", "symbols": ["Render", "render1"]}]
            },
        }
    ],
}


def db(tmp: Path, record: dict = GO_RECORD) -> tuple[SymbolDB, list[str]]:  # type: ignore[type-arg]
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/v1/query":
            return httpx.Response(
                200, json={"vulns": [{"id": "GHSA-2wrh", "aliases": ["CVE-2023-3978", record["id"]]}]}
            )
        return httpx.Response(200, json=record)

    return SymbolDB(httpx.Client(transport=httpx.MockTransport(handler)), tmp / "cache"), seen


def finding() -> Finding:
    return Finding(
        tool="trivy",
        rule_id="CVE-2023-3978",
        title="CVE-2023-3978 in golang.org/x/net",
        severity=Severity.MEDIUM,
        category=Category.SCA,
        confidence=Confidence.HIGH,
        location=Location(path="go.mod"),
        vuln_ids=["CVE-2023-3978"],
        package=Package(name="golang.org/x/net", version="v0.7.0", fixed_version="0.13.0", ecosystem="gomod"),
        fingerprint="fp",
    )


def scan(tmp: Path, code: str, symbols: SymbolDB, offline: bool = False) -> Finding:
    write(tmp, "go.mod", "module shop\n\nrequire golang.org/x/net v0.7.0\n")
    write(tmp, "main.go", code)
    f = finding()
    annotate_reachability(tmp, [f], Config(), offline=offline, symbols=symbols)
    score_all([f], Config())
    return f


CALLS = 'package main\n\nimport (\n\t"os"\n\th "golang.org/x/net/html"\n)\n\nfunc main() {\n\th.Render(os.Stdout, nil)\n}\n'


def test_call_to_the_vulnerable_function_is_evidence(tmp_path: Path) -> None:
    symbols, seen = db(tmp_path)
    f = scan(tmp_path, CALLS, symbols)
    assert f.package is not None and f.package.function_called is True
    assert f.package.vulnerable_functions == ["golang.org/x/net/html.Render"]  # unexported render1 dropped
    assert f.package.reach_evidence[0] == "main.go:9 calls Render"
    assert "first-party code calls the vulnerable function" in f.score_reasons
    assert seen == ["/v1/query", "/v1/vulns/GO-2023-1988"]
    scan(tmp_path, CALLS, symbols)  # cached: no new requests
    assert len(seen) == 2


def test_imported_but_not_called_directly(tmp_path: Path) -> None:
    symbols, _ = db(tmp_path)
    code = CALLS.replace("h.Render(os.Stdout, nil)", "h.Parse(os.Stdin)")
    f = scan(tmp_path, code, symbols)
    assert f.package is not None and f.package.function_called is False
    assert "does not call golang.org/x/net/html.Render directly" in f.package.reach_evidence[-1]
    assert "first-party code does not call the vulnerable function directly" in f.score_reasons


def test_vulnerable_package_not_imported_says_nothing(tmp_path: Path) -> None:
    record = json.loads(json.dumps(GO_RECORD))
    record["affected"][0]["ecosystem_specific"]["imports"][0]["path"] = "golang.org/x/net/http2"
    symbols, _ = db(tmp_path, record)
    f = scan(tmp_path, CALLS, symbols)
    assert f.package is not None and f.package.function_called is None
    assert "does not import directly (a dependency may still call it)" in f.package.reach_evidence[-1]


def test_offline_makes_no_requests(tmp_path: Path) -> None:
    symbols, seen = db(tmp_path)
    f = scan(tmp_path, CALLS, symbols, offline=True)
    assert seen == [] and f.package is not None and f.package.function_called is None


def test_default_package_names() -> None:
    assert _package_name("gopkg.in/yaml.v3") == "yaml"
    assert _package_name("github.com/acme/client/v2") == "client"
    assert _package_name("golang.org/x/net/html") == "html"
