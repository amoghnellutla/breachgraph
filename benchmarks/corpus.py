"""Run breachgraph on real projects that ship application code and deployment files together.

    python benchmarks/corpus.py select                 # pick projects by the rule below
    python benchmarks/corpus.py run                    # scan them with image breachgraph:dev
    python benchmarks/corpus.py run --fresh            # start over; without it, stored results stay
    python benchmarks/corpus.py run --only owner/repo  # one project
    python benchmarks/corpus.py summary                # the working numbers
    python benchmarks/corpus.py publish                # docs/real-world.md, counts only

The benchmark (run.py) measures training projects, where the attack chains are documented. This
measures what a real team would get: does it finish, how long does it take, what can't it see, and
are the paths it reports real.

The rule: public, not archived, not a fork, 1,000 stars or more, pushed in the last 180 days, under
1 GB, mostly Python, JavaScript, TypeScript, Java or Go, found under an application topic, and with
both HTTP-capable source and deployment files (Helm, Kustomize, Terraform or Kubernetes manifests).
The most-starred projects that pass are taken, without looking at what breachgraph finds in them.

Checkouts live in a Docker volume and results under .tmp/corpus/. Nothing is committed: findings in
other people's projects are reported to their maintainers privately, so only counts are published.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".tmp" / "corpus"
LIST = WORK / "corpus.json"
TOPICS = ("self-hosted", "saas", "web-application", "microservices", "open-source-alternative", "fullstack")
LANGUAGES = {"Python", "JavaScript", "TypeScript", "Java", "Go"}
MIN_STARS = 1000
MAX_SIZE_KB = 1_000_000
ACTIVE_DAYS = 180
SCAN_TIMEOUT_S = 1800
VOLUME = "breachgraph-corpus"
MODELED = ("routes", "workloads", "cloud_resources", "kubernetes_objects", "ci_jobs", "crown_jewels")
PUBLISHED = ROOT / "benchmarks" / "results" / "real-world.json"
PAGE = ROOT / "docs" / "real-world.md"
# What a release may not exceed. A first scan that blocks most projects teaches people to turn it off.
LIMITS = {"crashes": 0, "over_5_minutes": 0, "false_gating_paths": 0, "median_blocking_findings": 0}

_DEPLOY = {
    "helm": re.compile(r"(?:^|/)Chart\.yaml$"),
    "kustomize": re.compile(r"(?:^|/)kustomization\.ya?ml$"),
    "terraform": re.compile(r"\.tf$"),
    "kubernetes": re.compile(r"(?:^|/)(?:k8s|kube|kubernetes|manifests|deploy|deployment)/[^ ]*\.ya?ml$"),
}
_SOURCE = re.compile(r"\.(?:py|js|ts|tsx|java|go)$")


def gh(path: str) -> Any:
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8", check=False)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path}: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout)


def deployment_kinds(paths: list[str]) -> list[str]:
    return sorted(k for k, rx in _DEPLOY.items() if any(rx.search(p) for p in paths))


def passes(repo: dict[str, Any], now: datetime) -> bool:
    pushed = datetime.fromisoformat(repo["pushed_at"].replace("Z", "+00:00"))
    return bool(
        not repo["archived"]
        and not repo["fork"]
        and repo["stargazers_count"] >= MIN_STARS
        and repo["size"] <= MAX_SIZE_KB
        and repo.get("language") in LANGUAGES
        and now - pushed <= timedelta(days=ACTIVE_DAYS)
    )


def select(limit: int) -> int:
    now = datetime.now(UTC)
    found: dict[str, dict[str, Any]] = {}
    for topic in TOPICS:
        for page in (1, 2):
            q = f"topic:{topic}+stars:>={MIN_STARS}+fork:false+archived:false"
            data = gh(f"search/repositories?q={q}&sort=stars&per_page=100&page={page}")
            for repo in data["items"]:
                if passes(repo, now):
                    found[repo["full_name"]] = repo
            time.sleep(2.5)  # the search API allows 30 requests a minute
    chosen: list[dict[str, Any]] = []
    for name, repo in sorted(found.items(), key=lambda kv: -kv[1]["stargazers_count"]):
        if len(chosen) >= limit:
            break
        branch = repo["default_branch"]
        sha = gh(f"repos/{name}/commits/{branch}")["sha"]
        tree = gh(f"repos/{name}/git/trees/{sha}?recursive=1")
        paths = [t["path"] for t in tree["tree"] if t["type"] == "blob"]
        kinds = deployment_kinds(paths)
        if kinds and any(_SOURCE.search(p) for p in paths):
            chosen.append(
                {
                    "name": name,
                    "repo": repo["clone_url"],
                    "sha": sha,
                    "stars": repo["stargazers_count"],
                    "language": repo["language"],
                    "deploy": kinds,
                }
            )
            print(f"{len(chosen):>3} {name} ({repo['language']}, {', '.join(kinds)})")
    WORK.mkdir(parents=True, exist_ok=True)
    selected = now.date().isoformat()
    LIST.write_text(json.dumps({"selected": selected, "projects": chosen}, indent=2) + "\n", encoding="utf-8")
    print(f"{len(found)} projects passed the filters; {len(chosen)} chosen")
    return 0


def slug(name: str) -> str:
    return name.replace("/", "__")


def checkout(project: dict[str, Any], image: str) -> str:
    """Clone into a Docker volume, not the host: a bind mount from Windows or macOS costs minutes
    on a large tree, which CI runners don't pay. Returns the path inside the volume."""
    dest = f"/corpus/{slug(project['name'])}"
    script = (
        # Only a finished checkout counts: an interrupted clone leaves .git behind and no files.
        f"test -f {dest}.ready && exit 0; rm -rf {dest}; mkdir -p {dest} && cd {dest} && git init -q "
        f"&& git remote add origin {project['repo']} && git fetch -q --depth 1 origin {project['sha']} "
        "&& git -c advice.detachedHead=false checkout -q --force FETCH_HEAD "
        f'&& test -n "$(git ls-files | head -n 1)" && touch {dest}.ready'
    )
    for attempt in range(3):  # a long run outlives brief network failures
        try:
            subprocess.run(
                [
                    *("docker", "run", "--rm", "-v", f"{VOLUME}:/corpus"),
                    *("--entrypoint", "sh", image, "-c", script),
                ],
                check=True,
                capture_output=True,
                timeout=1800,
            )
            return dest
        except subprocess.SubprocessError:
            if attempt == 2:
                raise
            time.sleep(60)
    return dest


def scan(project: dict[str, Any], src: str, image: str) -> dict[str, Any]:
    out = WORK / "out" / slug(project["name"])
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        "breachgraph-corpus",
        "-v",
        f"{VOLUME}:/corpus",
        "-v",
        f"{out}:/out",
        "-v",
        f"{VOLUME}-cache:/tmp/breachgraph-cache",
        image,
        "scan",
        src,
        "-o",
        "/out",
        "-f",
        "json",
    ]
    started = time.monotonic()
    report = out / "breachgraph.json"
    report.unlink(missing_ok=True)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=SCAN_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", "breachgraph-corpus"], capture_output=True)
        return {"name": project["name"], "outcome": "timeout", "wall_time_s": SCAN_TIMEOUT_S}
    elapsed = round(time.monotonic() - started, 1)
    if proc.returncode not in (0, 1) or not report.is_file():
        return {
            "name": project["name"],
            "outcome": "crash",
            "exit": proc.returncode,
            "wall_time_s": elapsed,
            "stderr": proc.stderr[-3000:],
        }
    return measure(project, json.loads(report.read_text(encoding="utf-8")), elapsed)


def measure(project: dict[str, Any], report: dict[str, Any], elapsed: float) -> dict[str, Any]:
    ag = report.get("attack_graph") or {}
    modeled = {k: v for k, v in (ag.get("coverage") or {}).items() if k in MODELED and v}
    return {
        "name": project["name"],
        # Every project here has source and deployment files, so seeing nothing means no scan happened.
        "outcome": "ok" if report["findings"] or modeled else "empty",
        "deploy": project["deploy"],
        "wall_time_s": elapsed,
        "tools": {t["name"]: t["status"] for t in report["tools"]},
        "tool_seconds": {t["name"]: t.get("duration_s") for t in report["tools"]},
        "findings": sum(1 for f in report["findings"] if f["status"] != "suppressed"),
        "coverage": ag.get("coverage", {}),
        "blind_spots": ag.get("skipped", []),
        "paths": [
            {
                "route": " -> ".join(["Internet", *(s["dst"] for s in p["steps"])]),
                "confidence": p["confidence"],
                "gating": p["gating"],
                "weapons": [s["weakness_title"] for s in p["steps"] if s.get("via")],
                "evidence": [
                    f"{s['evidence_path']}:{s['evidence_line']}" for s in p["steps"] if s.get("evidence_path")
                ],
            }
            for p in ag.get("paths", [])
        ],
    }


def run(image: str, only: list[str]) -> int:
    projects = json.loads(LIST.read_text(encoding="utf-8"))["projects"]
    results = WORK / "results"
    results.mkdir(parents=True, exist_ok=True)
    # New volumes belong to root; the image runs as an unprivileged user.
    subprocess.run(
        [
            *("docker", "run", "--rm", "--user", "root", "--entrypoint", "chmod"),
            *("-v", f"{VOLUME}:/corpus", "-v", f"{VOLUME}-cache:/cache"),
            *(image, "1777", "/corpus", "/cache"),
        ],
        check=True,
        capture_output=True,
    )
    for project in projects:
        stored = results / f"{slug(project['name'])}.json"
        if only:
            if project["name"] not in only:
                continue
        elif stored.is_file():
            continue  # a long run can be resumed
        try:
            result = scan(project, checkout(project, image), image)
        except (subprocess.SubprocessError, OSError) as exc:
            result = {"name": project["name"], "outcome": "checkout failed", "error": str(exc)[:500]}
        stored.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"{result['outcome']:<8} {project['name']:<45} {result.get('wall_time_s', 0):>7}s "
            f"{result.get('findings', 0):>5} findings {len(result.get('paths', []))} paths",
            flush=True,
        )
    return 0


def blind_spot_cause(text: str) -> str:
    """Group blind spots: their text holds paths and names, the cause is what's left."""
    cause = text.split(": ", 1)[1] if ": " in text else text
    cause = re.sub(r"'[^']*'|`[^`]*`|\S*[/\\]\S*|\d+", "_", cause)
    return cause[:70]


def summary() -> int:
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((WORK / "results").glob("*.json"))]
    ok = [r for r in rows if r["outcome"] == "ok"]
    print(f"projects {len(rows)}: {dict(Counter(r['outcome'] for r in rows))}")
    times = sorted(r["wall_time_s"] for r in ok)
    if times:
        print(f"wall time: median {times[len(times) // 2]}s, max {times[-1]}s")
        print(f"over 5 minutes: {sum(1 for t in times if t > 300)}")
    print(f"findings: {sum(r['findings'] for r in ok)}")
    print(f"paths: {sum(len(r['paths']) for r in ok)} in {sum(1 for r in ok if r['paths'])} projects")
    print(f"no routes modeled: {sum(1 for r in ok if not r['coverage'].get('routes'))}")
    print(f"no workloads modeled: {sum(1 for r in ok if not r['coverage'].get('workloads'))}")
    print("tool problems:", dict(Counter(f"{k}={v}" for r in ok for k, v in r["tools"].items() if v != "ok")))
    print("top blind-spot causes:")
    causes = Counter(blind_spot_cause(s) for r in ok for s in r["blind_spots"])
    for cause, count in causes.most_common(20):
        print(f"  {count:>5}  {cause}")
    return 0


def counts(rows: list[dict[str, Any]], review: dict[str, int]) -> dict[str, Any]:
    """Aggregates only: nothing here names a project or a file."""
    ok = [r for r in rows if r["outcome"] == "ok"]
    files = [WORK / "out" / slug(r["name"]) / "breachgraph.json" for r in ok]
    reports = [json.loads(f.read_text(encoding="utf-8")) for f in files]
    blocking = [sum(1 for f in rep["findings"] if f.get("gating")) for rep in reports]
    gating = sum(1 for r in ok for p in r["paths"] if p["gating"])
    if review.get("real", 0) + review.get("false", 0) != gating:
        raise SystemExit(f"{gating} gating paths, {review} reviewed: label them in {WORK / 'review.json'}")
    times = sorted(r["wall_time_s"] for r in ok)
    return {
        "date": review["date"],
        "commit": review["commit"],
        "projects": len(rows),
        "crashes": len(rows) - len(ok),
        "median_seconds": times[len(times) // 2],
        "max_seconds": times[-1],
        "over_5_minutes": sum(1 for t in times if t > 300),
        "findings": sum(r["findings"] for r in ok),
        "paths": sum(len(r["paths"]) for r in ok),
        "projects_with_paths": sum(1 for r in ok if r["paths"]),
        "gating_paths": gating,
        "real_gating_paths": review["real"],
        "false_gating_paths": review["false"],
        "projects_passing": sum(
            1
            for rep, n in zip(reports, blocking, strict=True)
            if n == 0 and not any(p["gating"] for p in rep["attack_graph"]["paths"])
        ),
        "blocking_findings": sum(blocking),
        "median_blocking_findings": sorted(blocking)[len(blocking) // 2],
        "max_blocking_findings": max(blocking),
        "projects_one_bug_away": sum(1 for rep in reports if rep["attack_graph"].get("exposures")),
        "projects_modeling_nothing": sum(
            1 for r in ok if not r["coverage"].get("routes") and not r["coverage"].get("workloads")
        ),
    }


def render(c: dict[str, Any]) -> str:
    return f"""# breachgraph on real projects

The [benchmark](benchmark.md) measures breachgraph on projects that are vulnerable on purpose, where
the attack chains are documented. This page measures what a real team gets on a first scan: does it
finish, how long does it take, and is what it blocks worth blocking.

## Method

`benchmarks/corpus.py` picks projects by a written rule, without looking at what breachgraph finds
in them: public, not archived, not a fork, 1,000 stars or more, pushed in the last 180 days, under
1 GB, mostly Python, JavaScript, TypeScript, Java or Go, with both HTTP-capable source and
deployment files. The most-starred projects that pass are taken.

Each one gets a default first scan in the image built from the commit below, with no configuration
and no baseline.
Every path that blocks a merge was reviewed by reading the code. Nothing was run against any
project. Findings in other people's projects stay private, so only counts are given here and no
project is named.

Run on {c["date"]} at commit `{c["commit"]}`.

## Results

| | |
|---|---|
| Projects | {c["projects"]} |
| Crashes | {c["crashes"]} |
| Scan time, median | {c["median_seconds"]:.0f}s |
| Scan time, slowest | {c["max_seconds"]:.0f}s |
| Scans over 5 minutes | {c["over_5_minutes"]} |
| Findings reported | {c["findings"]:,} |
| Projects that pass a first scan | {c["projects_passing"]} of {c["projects"]} |
| Blocking findings per project, median | {c["median_blocking_findings"]} |
| Blocking findings per project, most | {c["max_blocking_findings"]} |
| Attack paths reported | {c["paths"]}, in {c["projects_with_paths"]} projects |
| Attack paths that block a merge | {c["gating_paths"]} |
| Of those, real on review | {c["real_gating_paths"]} |
| Of those, false | {c["false_gating_paths"]} |
| Projects told what one more bug would reach | {c["projects_one_bug_away"]} |

The other attack paths are low confidence: leads to read, which never block. Reading a path shows
that it holds in the code, but no path here was exploited to prove it.

## What this does not show

- The list is popular open-source projects, not private company code.
- {c["projects_modeling_nothing"]} of the {c["projects"]} projects gave breachgraph neither routes nor
  workloads to model, so it could only report their findings.
- A path reviewed as real still depends on what is deployed, which a repository only partly shows.
- Recall isn't measured here: nobody knows every path in these projects. The benchmark measures it
  on projects where the chains are documented.

## What it changed

Real code found what training projects couldn't. Across four passes, reviewing each result led to
fixes in the tool:

- Exploited isn't the same as control: a dependency CVE now needs a flaw that runs code before it
  can block a merge. Each of the three blocking paths that rested on a dependency CVE was false.
- Existing debt doesn't fail a first scan: one project went from 206 blocking findings to none.
- A secret is judged by its format, so checksums and placeholders stop blocking.
- Calls are followed from routes to helpers, and a route behind a login is labeled and ranked lower.
- Rule bugs were fixed, such as a database rule matching a web framework's `ctx.Query`.
- Graph building on a 10,000-file project went from over 6 minutes to well under one.

## Rerun it

```bash
python benchmarks/corpus.py select
python benchmarks/corpus.py run --fresh
python benchmarks/corpus.py summary
```

The project list is written to `.tmp/corpus/` and isn't committed. The rule above regenerates a list
for today's GitHub.
"""


def publish() -> int:
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((WORK / "results").glob("*.json"))]
    c = counts(rows, json.loads((WORK / "review.json").read_text(encoding="utf-8")))
    over = {k: c[k] for k, limit in LIMITS.items() if c[k] > limit}
    if over:
        print(f"over the limit, not published: {over}", file=sys.stderr)
        return 1
    PUBLISHED.write_text(json.dumps(c, indent=2) + "\n", encoding="utf-8", newline="\n")
    PAGE.write_text(render(c), encoding="utf-8", newline="\n")
    print(f"wrote {PAGE.name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("select", "run", "summary", "publish"))
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--image", default="breachgraph:dev")
    ap.add_argument("--fresh", action="store_true", help="discard stored results first")
    ap.add_argument("--only", action="append", default=[], help="project name (repeatable)")
    opts = ap.parse_args()
    if opts.command == "select":
        return select(opts.limit)
    if opts.command == "run":
        if opts.fresh:
            shutil.rmtree(WORK / "results", ignore_errors=True)
        return run(opts.image, opts.only)
    return publish() if opts.command == "publish" else summary()


if __name__ == "__main__":
    sys.exit(main())
