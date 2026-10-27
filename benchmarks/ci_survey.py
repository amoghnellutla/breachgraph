"""Run breachgraph's CI/CD checks on the GitHub Actions workflows of popular repositories.

    python benchmarks/ci_survey.py --top 100            # the most-starred repositories
    python benchmarks/ci_survey.py --repo owner/name    # specific ones (repeatable)
    python benchmarks/ci_survey.py --uses-trigger pull_request_target --min-stars 500 --limit 300
    python benchmarks/ci_survey.py --out summary.json --reanalyze   # after changing the checks

Only the workflow files are fetched (through the GitHub API, with GH_TOKEN), never the code.
Results go to .tmp/ci-survey/ and are NOT committed: a finding in someone else's CI is reported
to its maintainers privately first, and only counts are published once fixes have landed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from breachgraph.cicd import analyze

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / ".tmp" / "ci-survey"


def api(path: str) -> Any:
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "User-Agent": "breachgraph-ci-survey",
        },
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code in (403, 429) and attempt < 2:
                time.sleep(30)
                continue
            raise
    return None


def top_repos(n: int) -> list[str]:
    out: list[str] = []
    page = 1
    while len(out) < n:
        q = urllib.parse.quote("stars:>20000 archived:false")
        data = api(f"/search/repositories?q={q}&sort=stars&order=desc&per_page=100&page={page}")
        out += [r["full_name"] for r in data["items"] if not r.get("fork")]
        page += 1
    return out[:n]


def repos_using(trigger: str, min_stars: int, limit: int) -> list[str]:
    """Repositories whose workflows use a trigger (GitHub code search), popular ones only."""
    seen: dict[str, int] = {}
    for page in range(1, 11):  # code search returns at most 1,000 results
        q = urllib.parse.quote(f"{trigger} path:.github/workflows language:YAML")
        data = api(f"/search/code?q={q}&per_page=100&page={page}")
        items = (data or {}).get("items") or []
        for item in items:
            seen.setdefault(item["repository"]["full_name"], 0)
        if len(items) < 100:
            break
        time.sleep(7)  # code search allows 10 requests a minute
    out = []
    for repo in seen:
        meta = api(f"/repos/{repo}") or {}
        if meta.get("stargazers_count", 0) >= min_stars and not meta.get("archived") and not meta.get("fork"):
            out.append(repo)
        if len(out) >= limit:
            break
    return out


def fetch_workflows(repo: str, dest: Path) -> int:
    meta = api(f"/repos/{repo}")
    if not meta:
        return 0
    branch = meta["default_branch"]
    listing = api(f"/repos/{repo}/contents/.github/workflows?ref={urllib.parse.quote(branch)}") or []
    count = 0
    for item in listing:
        if item.get("type") != "file" or not item["name"].endswith((".yml", ".yaml")):
            continue
        blob = api(
            f"/repos/{repo}/contents/{urllib.parse.quote(item['path'])}?ref={urllib.parse.quote(branch)}"
        )
        if not blob or blob.get("encoding") != "base64":
            continue
        path = dest / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(blob["content"]))
        count += 1
    dest.mkdir(parents=True, exist_ok=True)
    head = api(f"/repos/{repo}/commits/{urllib.parse.quote(branch)}") or {}
    (dest / "COMMIT").write_text(f"{branch} {head.get('sha', '')}\n", encoding="utf-8")
    return count


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=0)
    ap.add_argument("--repo", action="append", default=[])
    ap.add_argument("--uses-trigger", default="")
    ap.add_argument("--min-stars", type=int, default=500)
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--out", default="summary.json")
    ap.add_argument("--reanalyze", action="store_true", help="re-run the checks on --out's cached repos")
    opts = ap.parse_args()
    if opts.reanalyze:  # no API calls: same repositories, same cached workflows
        opts.repo = [r["repo"] for r in json.loads((OUT / opts.out).read_text(encoding="utf-8"))]
        opts.top, opts.uses_trigger = 0, ""
    repos = [*opts.repo, *(top_repos(opts.top) if opts.top else [])]
    if opts.uses_trigger:
        repos += repos_using(opts.uses_trigger, opts.min_stars, opts.limit)
    OUT.mkdir(parents=True, exist_ok=True)
    summary: list[dict[str, Any]] = []
    for repo in repos:
        dest = OUT / "repos" / repo.replace("/", "__")
        if not (dest / "COMMIT").is_file():
            fetch_workflows(repo, dest)
        findings, _ = analyze(dest, []) if dest.is_dir() else ([], [])
        rows = [
            {
                "rule": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "where": f"{f.location.path}:{f.location.start_line}",
                "title": f.title,
                "snippet": f.location.snippet,
            }
            for f in findings
        ]
        workflows = len(list((dest / ".github" / "workflows").glob("*.y*ml"))) if dest.is_dir() else 0
        summary.append({"repo": repo, "workflows": workflows, "findings": rows})
        print(f"{repo:<45} {workflows:>3} workflows {len(rows):>3} findings", flush=True)
    (OUT / opts.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    total = sum(len(s["findings"]) for s in summary)
    hit = sum(1 for s in summary if s["findings"])
    print(
        f"\n{len(summary)} repositories, {sum(s['workflows'] for s in summary)} workflows, "
        f"{total} findings in {hit} repositories"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
