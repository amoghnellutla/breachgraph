# Benchmark

How well breachgraph works on real projects, measured the same way every time. The published
results are in [docs/benchmark.md](../docs/benchmark.md).

| File | What it is |
|---|---|
| `targets.yml` | The projects, each pinned to a commit. They are cloned at run time and never vendored |
| `run.py` | Clones each target and scans it with the Docker image, writing `results/<name>.json` |
| `results/` | One compact summary per target: counts, tools, attack paths, blind spots |
| `labels/` | A hand review of every reported attack path, plus scenarios breachgraph missed |
| `report.py` | Builds `docs/benchmark.md` from results and labels; `--check` fails if any path is unlabeled or the page is stale (CI runs it as a test) |

## Labeling

Each path in `results/<name>.json` gets an entry in `labels/<name>.yml`, matched by `key`:

```yaml
summary: One paragraph on what the project is and what breachgraph found.
paths:
  - key: "Internet -> GCS bucket terragoat_website"
    verdict: true        # true | false | unclear
    why: allUsers has roles/storage.objectViewer on the bucket (gcs.tf:17).
misses:
  - scenario: Publicly accessible RDS instance (db-app.tf:22).
    why: Reported as exposure; no path without database credentials, by design.
```

A path is `true` when an attacker could really use it given the project's documented scenario,
and `false` when it couldn't. `unclear` is for cases that depend on something outside the
repository. Be strict: precision is only worth something if `false` is used when it applies.

## Running

```bash
docker build -t breachgraph:dev .
python benchmarks/run.py                 # all targets (about an hour)
python benchmarks/run.py --only gcpgoat  # one target
python benchmarks/report.py              # rebuild docs/benchmark.md
```

Bumping a target's commit or breachgraph's version changes results: re-run, re-label any path
whose key changed, and rebuild the page.
