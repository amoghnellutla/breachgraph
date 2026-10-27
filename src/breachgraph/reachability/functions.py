"""Function-level reachability for Go: is the vulnerable function itself called?

The Go vulnerability database (published through OSV as GO-* records) names the exact package and
symbols each vulnerability lives in, e.g. golang.org/x/net/html: Render. When first-party code
imports that package, its calls are searched for those symbols. A call is evidence (file:line);
no call means the import alone does not reach the bug, and the finding is deprioritized.

Limits, kept honest in the evidence text: calls are matched by name in files that import the
package (an interface call through another package is not seen), methods match by method name,
and only Go has symbol data in OSV at the moment. Everything else stays import-level.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import httpx

from breachgraph.enrich import cache_dir

OSV = "https://api.osv.dev/v1"
_MAX_AGE = 7 * 86400
_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:([A-Za-z_][\w]*|\.)\s+)?"([^"]+)"', re.M)


class SymbolDB:
    """GO-* records from OSV, cached on disk for a week."""

    def __init__(self, client: httpx.Client | None = None, cache: Path | None = None) -> None:
        self.client = client or httpx.Client(timeout=20)
        self.cache = (cache or cache_dir()) / "osv"
        self.cache.mkdir(parents=True, exist_ok=True)

    def _get(self, key: str, fetch: Any) -> Any:
        file = self.cache / (re.sub(r"[^\w.-]", "_", key) + ".json")
        if file.exists() and time.time() - file.stat().st_mtime < _MAX_AGE:
            return json.loads(file.read_text(encoding="utf-8"))
        data = fetch()
        file.write_text(json.dumps(data), encoding="utf-8")
        return data

    def go_ids(self, module: str, version: str, vuln_ids: list[str]) -> list[str]:
        """GO-* ids for these CVE/GHSA ids, via an OSV query for the module at this version."""
        direct = [v for v in vuln_ids if v.startswith("GO-")]
        if direct:
            return direct

        def fetch() -> Any:
            resp = self.client.post(
                f"{OSV}/query",
                json={"package": {"ecosystem": "Go", "name": module}, "version": version.lstrip("v")},
            )
            resp.raise_for_status()
            return [[v["id"], *(v.get("aliases") or [])] for v in resp.json().get("vulns") or []]

        wanted = set(vuln_ids)
        out: list[str] = []
        for ids in self._get(f"q-{module}@{version}", fetch):
            if wanted & set(ids):
                out += [i for i in ids if i.startswith("GO-") and i not in out]
        return out

    def symbols(self, go_id: str, module: str) -> dict[str, list[str]]:
        """{package import path: exported vulnerable symbols} for the module in a GO-* record."""

        def fetch() -> Any:
            resp = self.client.get(f"{OSV}/vulns/{go_id}")
            resp.raise_for_status()
            return resp.json()

        out: dict[str, list[str]] = {}
        for affected in self._get(go_id, fetch).get("affected") or []:
            if (affected.get("package") or {}).get("name") != module:
                continue
            for imp in (affected.get("ecosystem_specific") or {}).get("imports") or []:
                exported = [s for s in imp.get("symbols") or [] if s.split(".")[-1][:1].isupper()]
                if exported:
                    out.setdefault(imp["path"], []).extend(exported)
        return out


def go_calls(target: Path, files: list[str], symbols: dict[str, list[str]]) -> list[str]:
    """file:line of each call to a vulnerable symbol in first-party Go files."""
    hits: list[str] = []
    for rel in files:
        try:
            text = (target / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        aliases = {m.group(2): m.group(1) or _package_name(m.group(2)) for m in _IMPORT.finditer(text)}
        for pkg_path, syms in symbols.items():
            alias = aliases.get(pkg_path)
            if alias is None:
                continue
            for sym in syms:
                if "." in sym:  # Type.Method: matched by method name in a file that imports the package
                    pattern = re.compile(rf"\.{re.escape(sym.split('.')[-1])}\s*\(")
                elif alias == ".":
                    pattern = re.compile(rf"(?<![\w.]){re.escape(sym)}\s*\(")
                else:
                    pattern = re.compile(rf"\b{re.escape(alias)}\.{re.escape(sym)}\s*\(")
                for m in pattern.finditer(text):
                    hits.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1} calls {sym}")
    return sorted(set(hits))


def _package_name(path: str) -> str:
    """Default package name of an import path: gopkg.in/yaml.v3 -> yaml, github.com/x/y/v2 -> y."""
    parts = path.split("/")
    last = parts[-1]
    if re.fullmatch(r"v\d+", last) and len(parts) > 1:
        last = parts[-2]
    return re.sub(r"\.v\d+$", "", last).replace("-", "_")
