"""OpenVEX v0.2.0 from reachability: which dependency CVEs actually affect the scanned product.

The product is the scanned application, each vulnerable package is a subcomponent:

- the package is never imported by first-party code  -> ``not_affected``,
  ``vulnerable_code_not_in_execute_path``, with the evidence;
- it is imported (reachable from an entry point or not) -> ``affected``, with the upgrade;
- reachability could not be determined               -> ``under_investigation``.

Reachability is import-level, so ``not_affected`` means "no first-party module imports it". Code
that loads packages dynamically (importlib, reflection, plugins) can defeat that; teams that
cannot rule this out set ``vex.not_affected: false`` to emit ``under_investigation`` instead.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from breachgraph.models import Category, Finding, Reachability, ScanResult, Status

CONTEXT = "https://openvex.dev/ns/v0.2.0"
# Trivy package types / ecosystems -> purl types.
_PURL_TYPE = {
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "uv": "pypi",
    "python-pkg": "pypi",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "node-pkg": "npm",
    "pom": "maven",
    "gradle": "maven",
    "jar": "maven",
    "gomod": "golang",
    "gobinary": "golang",
    "cargo": "cargo",
    "bundler": "gem",
    "gemspec": "gem",
    "nuget": "nuget",
    "composer": "composer",
}


def purl(f: Finding) -> str | None:
    pkg = f.package
    if pkg is None:
        return None
    if pkg.purl:
        return pkg.purl
    kind = _PURL_TYPE.get((pkg.ecosystem or "").lower())
    if kind is None or not pkg.version:
        return None
    name = pkg.name.replace(":", "/") if kind == "maven" else pkg.name.lower() if kind == "pypi" else pkg.name
    return f"pkg:{kind}/{name}@{pkg.version}"


def _products(f: Finding, sub: str, product: str | None) -> list[dict[str, Any]]:
    """Scope the statement as precisely as consumers can match it.

    VEX consumers (Trivy, Grype) match products against components found in a scan. When the
    manifest has a root component (pom.xml, go.mod, package.json), or the user names the product,
    the statement is "this package inside this product". A plain requirements file has no root,
    so the package itself is the product, scoped by whoever applies this document to their scan."""
    root = product or (f.package.root_purl if f.package else None)
    if root:
        return [{"@id": root, "subcomponents": [{"@id": sub}]}]
    return [{"@id": sub}]


def _statement(f: Finding, product: str | None, allow_not_affected: bool) -> dict[str, Any] | None:
    sub = purl(f)
    if sub is None or not f.vuln_ids:
        return None
    cves = [v for v in f.vuln_ids if v.upper().startswith("CVE-")]
    name = cves[0] if cves else f.vuln_ids[0]
    vuln: dict[str, Any] = {"name": name}
    aliases = sorted({v for v in f.vuln_ids if v != name})
    if aliases:
        vuln["aliases"] = aliases
    statement: dict[str, Any] = {
        "vulnerability": vuln,
        "products": _products(f, sub, product),
    }
    pkg_name = f.package.name if f.package else "the package"
    reach = f.package.reachability if f.package else None
    evidence = "; ".join((f.package.reach_evidence if f.package else [])[:3])
    if reach is Reachability.UNUSED and allow_not_affected:
        statement["status"] = "not_affected"
        statement["justification"] = "vulnerable_code_not_in_execute_path"
        statement["impact_statement"] = (
            f"No first-party module imports {pkg_name}; it is only a "
            "declared or transitive dependency (breachgraph import-level reachability)."
            + (f" {evidence}" if evidence else "")
        )
    elif reach in (Reachability.ENTRYPOINT, Reachability.DIRECT):
        statement["status"] = "affected"
        where = "reachable from an HTTP entry point" if reach is Reachability.ENTRYPOINT else "imported"
        fix = f.package.fixed_version if f.package else None
        statement["action_statement"] = (
            f"Upgrade {pkg_name} to {fix.split(',')[0].strip()} or later."
            if fix
            else "No fixed version yet: apply vendor mitigations or replace the package."
        )
        statement["status_notes"] = f"The package is {where} in first-party code." + (
            f" {evidence}" if evidence else ""
        )
    else:
        statement["status"] = "under_investigation"
        statement["status_notes"] = (
            "Import-level reachability says the package is unused, but not_affected statements are disabled."
            if reach is Reachability.UNUSED
            else "breachgraph could not determine whether first-party code uses this package."
        )
    return statement


def build(result: ScanResult) -> dict[str, Any]:
    raw = result.metadata.get("vex")
    settings: dict[str, Any] = raw if isinstance(raw, dict) else {}
    product = str(settings["product"]) if settings.get("product") else None
    allow = bool(settings.get("not_affected", True))
    statements: dict[tuple[str, str], dict[str, Any]] = {}
    for f in result.findings:
        if f.category is not Category.SCA or not f.location.in_repo or f.status is Status.SUPPRESSED:
            continue
        st = _statement(f, product, allow)
        if st is None:
            continue
        key = (st["vulnerability"]["name"], json.dumps(st["products"], sort_keys=True))
        statements.setdefault(key, st)
    issued = (result.finished_at or result.started_at).isoformat().replace("+00:00", "Z")
    ordered = [statements[k] for k in sorted(statements)]
    digest = hashlib.sha256(json.dumps([product, ordered], sort_keys=True).encode()).hexdigest()[:16]
    return {
        "@context": CONTEXT,
        "@id": f"urn:breachgraph:vex:{digest}",
        "author": str(settings.get("author") or "breachgraph"),
        "role": "Document Creator",
        "timestamp": issued,
        "version": 1,
        "tooling": f"breachgraph {result.breachgraph_version} (import-level reachability)",
        "statements": ordered,
    }


def render(result: ScanResult) -> str:
    return json.dumps(build(result), indent=2) + "\n"
