"""Exploit-likelihood enrichment for CVE findings.

* CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed in-the-wild exploitation.
* FIRST EPSS: probability (0-1) that a CVE is exploited in the next 30 days.

Both are free public feeds. Results are cached on disk; if the network is unavailable the scan
still completes and a warning is recorded.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from secgate import __version__
from secgate.config import Enrich
from secgate.models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_BATCH = 100
_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


def cache_dir() -> Path:
    if explicit := os.environ.get("SECGATE_CACHE_DIR"):
        path = Path(explicit)
    else:
        path = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "secgate"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _fresh(path: Path, max_age_s: float) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < max_age_s


def load_kev(client: httpx.Client, cache: Path, max_age_s: float) -> dict[str, dict[str, Any]]:
    file = cache / "kev.json"
    if not _fresh(file, max_age_s):
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        file.write_text(resp.text, encoding="utf-8")
    data = json.loads(file.read_text(encoding="utf-8"))
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if v.get("cveID")}


def load_epss(
    client: httpx.Client, cves: list[str], cache: Path, max_age_s: float
) -> dict[str, tuple[float, float]]:
    file = cache / "epss.json"
    try:
        stored: dict[str, Any] = (
            json.loads(file.read_text(encoding="utf-8")) if file.exists() else {}
        )
    except json.JSONDecodeError:
        stored = {}
    now = time.time()
    missing = [c for c in cves if c not in stored or now - stored[c]["fetched"] > max_age_s]
    for i in range(0, len(missing), _EPSS_BATCH):
        batch = missing[i : i + _EPSS_BATCH]
        resp = client.get(EPSS_URL, params={"cve": ",".join(batch), "limit": len(batch)})
        resp.raise_for_status()
        returned = set()
        for row in resp.json().get("data", []):
            cve = row["cve"].upper()
            returned.add(cve)
            stored[cve] = {
                "epss": float(row["epss"]),
                "pct": float(row["percentile"]),
                "fetched": now,
            }
        for cve in set(batch) - returned:  # unknown to EPSS (too new / reserved): cache as 0
            stored[cve] = {"epss": None, "pct": None, "fetched": now}
    if missing:
        file.write_text(json.dumps(stored), encoding="utf-8")
    return {
        c: (stored[c]["epss"], stored[c]["pct"])
        for c in cves
        if stored.get(c, {}).get("epss") is not None
    }


def enrich(findings: list[Finding], cfg: Enrich, offline: bool = False) -> list[str]:
    """Fill ``finding.enrichment`` in place. Returns warnings (never raises on network errors)."""
    cves = sorted({c.upper() for f in findings for c in f.cves})
    if not cves or offline or not (cfg.kev or cfg.epss):
        return []
    warnings: list[str] = []
    cache = cache_dir()
    max_age = cfg.cache_hours * 3600
    kev: dict[str, dict[str, Any]] = {}
    epss: dict[str, tuple[float, float]] = {}
    headers = {"User-Agent": f"secgate/{__version__}"}
    with httpx.Client(timeout=_TIMEOUT, headers=headers, follow_redirects=True) as client:
        if cfg.kev:
            try:
                kev = load_kev(client, cache, max_age)
            except (httpx.HTTPError, ValueError, OSError) as exc:
                warnings.append(f"CISA KEV enrichment unavailable: {exc}")
        if cfg.epss:
            try:
                epss = load_epss(client, cves, cache, max_age)
            except (httpx.HTTPError, ValueError, OSError, KeyError) as exc:
                warnings.append(f"EPSS enrichment unavailable: {exc}")
    for f in findings:
        for cve in (c.upper() for c in f.cves):
            if cve in kev:
                f.enrichment.kev = True
                f.enrichment.kev_date_added = kev[cve].get("dateAdded")
                f.enrichment.kev_ransomware = kev[cve].get("knownRansomwareCampaignUse") == "Known"
            if cve in epss:
                score, pct = epss[cve]
                if f.enrichment.epss is None or score > f.enrichment.epss:
                    f.enrichment.epss, f.enrichment.epss_percentile = score, pct
    return warnings
