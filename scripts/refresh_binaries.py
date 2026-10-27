"""Move the Trivy and Gitleaks pins in the Dockerfile to their newest settled release.

    python scripts/refresh_binaries.py          # update the Dockerfile in place
    python scripts/refresh_binaries.py --check  # only print what would change

A release is taken only when it is at least COOLDOWN_DAYS old and not a prerelease, so a
compromised or broken release has time to be noticed and pulled first. The SHA-256 values come
from the release's own checksums file; the Docker build verifies every download against them.
Set GH_TOKEN (or GITHUB_TOKEN) to avoid the GitHub API's anonymous rate limit.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
COOLDOWN_DAYS = 14
# ARG prefix -> (repository, checksums file, {arch: release file}); {v} is the version.
TOOLS: dict[str, tuple[str, str, dict[str, str]]] = {
    "TRIVY": (
        "aquasecurity/trivy",
        "trivy_{v}_checksums.txt",
        {"AMD64": "trivy_{v}_Linux-64bit.tar.gz", "ARM64": "trivy_{v}_Linux-ARM64.tar.gz"},
    ),
    "GITLEAKS": (
        "gitleaks/gitleaks",
        "gitleaks_{v}_checksums.txt",
        {"AMD64": "gitleaks_{v}_linux_x64.tar.gz", "ARM64": "gitleaks_{v}_linux_arm64.tar.gz"},
    ),
}


def _get(url: str) -> bytes:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "breachgraph-refresh"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:  # noqa: S310
        data: bytes = resp.read()
        return data


def settled_release(repo: str, now: datetime) -> str | None:
    """Newest non-draft, non-prerelease version published at least COOLDOWN_DAYS ago."""
    releases: list[dict[str, Any]] = json.loads(
        _get(f"https://api.github.com/repos/{repo}/releases?per_page=30")
    )
    cutoff = now - timedelta(days=COOLDOWN_DAYS)
    for rel in releases:  # newest first
        if rel.get("draft") or rel.get("prerelease") or not rel.get("published_at"):
            continue
        if datetime.fromisoformat(rel["published_at"].replace("Z", "+00:00")) <= cutoff:
            return str(rel["tag_name"]).removeprefix("v")
    return None


def checksums(repo: str, version: str, sums_file: str) -> dict[str, str]:
    url = f"https://github.com/{repo}/releases/download/v{version}/{sums_file.format(v=version)}"
    out: dict[str, str] = {}
    for line in _get(url).decode().splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            out[parts[1].lstrip("*")] = parts[0]
    return out


def refresh(text: str, now: datetime) -> tuple[str, list[str]]:
    changes: list[str] = []
    for prefix, (repo, sums_file, files) in TOOLS.items():
        current = re.search(rf"^ARG {prefix}_VERSION=(\S+)$", text, re.M)
        version = settled_release(repo, now)
        if current is None or version is None or version == current.group(1):
            continue
        sums = checksums(repo, version, sums_file)
        new = {arch: sums.get(name.format(v=version)) for arch, name in files.items()}
        if not all(new.values()):
            changes.append(f"{prefix.lower()} {version}: checksums missing, not updated")
            continue
        text = re.sub(rf"^ARG {prefix}_VERSION=\S+$", f"ARG {prefix}_VERSION={version}", text, flags=re.M)
        for arch, sha in new.items():
            text = re.sub(
                rf"^ARG {prefix}_SHA256_{arch}=\S+$", f"ARG {prefix}_SHA256_{arch}={sha}", text, flags=re.M
            )
        changes.append(f"{prefix.lower()} {current.group(1)} -> {version}")
    return text, changes


def main() -> int:
    text = DOCKERFILE.read_text(encoding="utf-8")
    updated, changes = refresh(text, datetime.now(UTC))
    for change in changes:
        print(change)
    if updated != text and "--check" not in sys.argv[1:]:
        DOCKERFILE.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
