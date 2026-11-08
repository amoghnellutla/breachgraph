# breachgraph on real projects

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

Run on 2026-11-08 at commit `23c90d8`.

Correction: the version of this page released with 0.7.0 was wrong. Seven of its 51 scans had run on
an interrupted checkout with no files, and those scans counted as clean passes, so it overstated
how many projects pass and understated findings. The corpus now rejects a checkout with no files and
treats a scan that saw nothing as a failure, which stops a release from publishing one.

## Results

| | |
|---|---|
| Projects | 51 |
| Crashes | 0 |
| Scan time, median | 34s |
| Scan time, slowest | 255s |
| Scans over 5 minutes | 0 |
| Findings reported | 24,877 |
| Projects that pass a first scan | 48 of 51 |
| Blocking findings per project, median | 0 |
| Blocking findings per project, most | 1 |
| Attack paths reported | 74, in 18 projects |
| Attack paths that block a merge | 2 |
| Of those, real on review | 2 |
| Of those, false | 0 |
| Projects told what one more bug would reach | 34 |

The other attack paths are low confidence: leads to read, which never block. They are noisy. In a
random sample of 16, before the last rule fix, about 2 looked real. Reading a path shows that it holds
in the code, but no path here was exploited to prove it.

## Would it have found real vulnerabilities?

Precision can't show what a tool misses, so `benchmarks/recall.py` takes reviewed GitHub advisories by
a written rule: the newest HIGH or CRITICAL ones in npm, PyPI, Go and Maven for weaknesses breachgraph
has rules for, each with a linked fix commit. It scans the commit just before the fix and counts
whether a code finding lands within 5 lines of a line the fix changed, or only in a file it
changed. Fixes often land apart from the flaw, as validation or a new default, so the first column
undercounts and the second can overcount.

| Weakness | On the fixed lines | In a fixed file | Cases |
|---|---:|---:|---:|
| SQL injection | 0 | 0 | 1 |
| SSRF | 0 | 0 | 3 |
| code injection | 1 | 1 | 7 |
| command injection | 6 | 7 | 13 |
| deserialization | 0 | 1 | 3 |
| path traversal | 3 | 4 | 12 |
| All | 10 | 13 | 39 |

Reading the misses shows why. Most are logic bugs in libraries, not a value reaching a dangerous
call, and no rule finds those without also flagging correct code. So read this as a floor for what
attack paths can start from, and as the reason a path's absence never means a repository is safe.

## What this does not show

- The list is popular open-source projects, not private company code.
- 0 of the 51 projects gave breachgraph neither routes nor
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
- Charts in a directory named `charts/`, the usual layout, were being skipped as subcharts. Rendering
  them took blind spots from 312 to 68.

## Rerun it

```bash
python benchmarks/corpus.py select
python benchmarks/corpus.py run --fresh
python benchmarks/corpus.py summary
```

The project list is written to `.tmp/corpus/` and isn't committed. The rule above regenerates a list
for today's GitHub.
