"""Would breachgraph have found real vulnerabilities? Scan the commit just before each one was fixed.

    python benchmarks/recall.py select --limit 40   # pick advisories by the rule below
    python benchmarks/recall.py run                 # scan each with image breachgraph:dev
    python benchmarks/recall.py summary             # counts for docs/real-world.md

The precision pages can't say what breachgraph misses. Here the answer is known: a security advisory
names the fix, so the lines it changed are the vulnerable code.

The rule: reviewed GitHub advisories, newest first, HIGH or CRITICAL, in npm, PyPI, Go or Maven, whose
weakness is one breachgraph has rules for (command injection, code injection, deserialization, SQL
injection, path traversal, SSRF), with a linked fix commit that changes non-test source files. No
advisory is picked by looking at what breachgraph finds.

A case counts on the line when a code finding lands within a few lines of a line the fix changed,
and in the file when it only lands in a file the fix changed.
Work stays under .tmp/corpus/, as corpus.py does. Advisories are public, so results can name them.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from typing import Any

import corpus

WORK = corpus.WORK / "recall"
LIST = WORK / "advisories.json"
RESULTS = WORK / "results"
WINDOW = corpus.RECALL_WINDOW  # lines around a changed line
CLASSES = {
    "CWE-78": "command injection",
    "CWE-77": "command injection",
    "CWE-94": "code injection",
    "CWE-95": "code injection",
    "CWE-502": "deserialization",
    "CWE-89": "SQL injection",
    "CWE-22": "path traversal",
    "CWE-23": "path traversal",
    "CWE-918": "SSRF",
}
_SOURCE = re.compile(r"\.(?:py|js|jsx|ts|tsx|java|go)$")
_TESTS = re.compile(
    r"(?:^|/)(?:tests?|__tests__|testdata|spec|e2e)/|[._-](?:test|spec)\.|(?:^|/)test_|_test\."
)
_COMMIT = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? ", re.M)
QUERY = """
query($after: String) {
  securityVulnerabilities(first: 100, after: $after, ecosystem: %s,
                          orderBy: {field: UPDATED_AT, direction: DESC}) {
    pageInfo { endCursor hasNextPage }
    nodes { severity advisory { ghsaId withdrawnAt publishedAt
      cwes(first: 5) { nodes { cweId } } references { url } } }
  }
}
"""


def graphql(query: str, after: str | None) -> Any:
    args = ["gh", "api", "graphql", "-f", f"query={query}"]
    if after:
        args += ["-f", f"after={after}"]
    out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", check=False)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    return json.loads(out.stdout)["data"]["securityVulnerabilities"]


def changed_source(repo: str, sha: str) -> dict[str, Any] | None:
    """The fix's parent and the old-side lines it changed in non-test source files."""
    try:
        commit = corpus.gh(f"repos/{repo}/commits/{sha}")
    except RuntimeError:
        return None
    lines: dict[str, list[list[int]]] = {}
    for f in commit.get("files") or []:
        name = f.get("filename", "")
        if not _SOURCE.search(name) or _TESTS.search(name) or not f.get("patch"):
            continue
        lines[name] = [[int(m[1]), int(m[1]) + int(m[2] or 1)] for m in _HUNK.finditer(f["patch"])]
    parents = commit.get("parents") or []
    return {"parent": parents[0]["sha"], "lines": lines} if lines and parents else None


def select(limit: int) -> int:
    picked: dict[str, dict[str, Any]] = {}
    for ecosystem in ("NPM", "PIP", "GO", "MAVEN"):
        after = None
        for _page in range(12):
            page = graphql(QUERY % ecosystem, after)
            for node in page["nodes"]:
                adv = node["advisory"]
                cwes = [c["cweId"] for c in adv["cwes"]["nodes"] if c["cweId"] in CLASSES]
                url = next((m for r in adv["references"] if (m := _COMMIT.search(r["url"]))), None)
                wanted = node["severity"] in ("HIGH", "CRITICAL") and cwes and url and not adv["withdrawnAt"]
                if not wanted or adv["ghsaId"] in picked or url is None:
                    continue
                change = changed_source(url.group(1), url.group(2))
                if change:
                    picked[adv["ghsaId"]] = {
                        "id": adv["ghsaId"],
                        "name": f"recall/{adv['ghsaId']}",
                        "repo": f"https://github.com/{url.group(1)}",
                        "sha": change["parent"],
                        "deploy": [],
                        "published": adv["publishedAt"],
                        "weakness": CLASSES[cwes[0]],
                        "lines": change["lines"],
                    }
            after = page["pageInfo"]["endCursor"]
            if not page["pageInfo"]["hasNextPage"]:
                break
    newest = sorted(picked.values(), key=lambda a: a["published"], reverse=True)[:limit]
    WORK.mkdir(parents=True, exist_ok=True)
    LIST.write_text(json.dumps(newest, indent=2), encoding="utf-8")
    print(Counter(a["weakness"] for a in newest))
    return 0


def found(report: dict[str, Any], lines: dict[str, list[list[int]]]) -> str | None:
    """ "line" when a finding sits on the fix, "file" when it's only in a file the fix changed. Fixes
    often land apart from the flaw, as validation or a new default, so a line alone undercounts."""
    best = None
    for f in report["findings"]:
        loc = f["location"]
        if f["category"] != "sast" or not loc.get("start_line") or loc["path"] not in lines:
            continue
        best = "file"
        for start, end in lines[loc["path"]]:
            if start - WINDOW <= loc["start_line"] <= end + WINDOW:
                return "line"
    return best


def rules_in(report: dict[str, Any], lines: dict[str, list[list[int]]]) -> list[str]:
    """Which rules touched the fixed files, so each rule has to earn its noise."""
    return sorted(
        {
            f["rule_id"]
            for f in report["findings"]
            if f["category"] == "sast" and f["location"]["path"] in lines
        }
    )


def run(image: str) -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    for case in json.loads(LIST.read_text(encoding="utf-8")):
        stored = RESULTS / f"{case['id']}.json"
        if stored.is_file():
            continue
        try:
            scanned = corpus.scan(case, corpus.checkout(case, image), image)
        except (subprocess.SubprocessError, OSError) as exc:
            scanned = {"outcome": "checkout failed", "error": str(exc)[:300]}
        report = corpus.WORK / "out" / corpus.slug(case["name"]) / "breachgraph.json"
        hit, rules = None, []
        if scanned["outcome"] == "ok":
            parsed = json.loads(report.read_text(encoding="utf-8"))
            hit, rules = found(parsed, case["lines"]), rules_in(parsed, case["lines"])
        row = {
            "id": case["id"],
            "weakness": case["weakness"],
            "outcome": scanned["outcome"],
            "found": hit,
            "rules": rules,
        }
        stored.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
        shutil.rmtree(report.parent, ignore_errors=True)
        print(f"{case['id']} {case['weakness']:<20} {scanned['outcome']:<8} {hit}", flush=True)
    return 0


def tally(rows: list[dict[str, Any]]) -> dict[str, Any]:
    done = [r for r in rows if r["outcome"] == "ok"]
    by: dict[str, list[int]] = {}
    for r in done:
        row = by.setdefault(r["weakness"], [0, 0, 0])
        row[0] += r["found"] == "line"
        row[1] += bool(r["found"])
        row[2] += 1
    on_line = sum(r["found"] == "line" for r in done)
    in_file = sum(bool(r["found"]) for r in done)
    return {"cases": len(done), "on_line": on_line, "in_file": in_file, "by_weakness": by}


def summary() -> int:
    result = tally([json.loads(p.read_text(encoding="utf-8")) for p in RESULTS.glob("*.json")])
    (WORK / "summary.json").write_text(json.dumps(result), encoding="utf-8")
    print(json.dumps(result))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("select", "run", "summary"))
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--image", default="breachgraph:dev")
    opts = ap.parse_args()
    if opts.command == "select":
        return select(opts.limit)
    return run(opts.image) if opts.command == "run" else summary()


if __name__ == "__main__":
    sys.exit(main())
