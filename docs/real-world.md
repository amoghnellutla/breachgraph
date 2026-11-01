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

Run on 2026-11-01 at commit `bf2f507`. The clock includes a cold start for the first project,
which downloads the scanners' vulnerability databases.

Correction: the version of this page released with 0.7.0 was wrong. Seven of its 51 scans had run on
an interrupted checkout with no files, and those scans counted as clean passes, so it overstated
how many projects pass and understated findings. The corpus now rejects a checkout with no files and
treats a scan that saw nothing as a failure, which stops a release from publishing one.

## Results

| | |
|---|---|
| Projects | 51 |
| Crashes | 0 |
| Scan time, median | 44s |
| Scan time, slowest | 277s |
| Scans over 5 minutes | 0 |
| Findings reported | 25,256 |
| Projects that pass a first scan | 46 of 51 |
| Blocking findings per project, median | 0 |
| Blocking findings per project, most | 1 |
| Attack paths reported | 73, in 18 projects |
| Attack paths that block a merge | 2 |
| Of those, real on review | 2 |
| Of those, false | 0 |
| Projects told what one more bug would reach | 35 |

The other attack paths are low confidence: leads to read, which never block. Reading a path shows
that it holds in the code, but no path here was exploited to prove it.

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

## Rerun it

```bash
python benchmarks/corpus.py select
python benchmarks/corpus.py run --fresh
python benchmarks/corpus.py summary
```

The project list is written to `.tmp/corpus/` and isn't committed. The rule above regenerates a list
for today's GitHub.
