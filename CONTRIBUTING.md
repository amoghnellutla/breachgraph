# Contributing

Thanks for helping make breachgraph better!

## Development setup

```bash
git clone https://github.com/amoghnellutla/breachgraph && cd breachgraph
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/check.py          # format, lint, mypy and tests, like CI (--fix applies ruff fixes)
```

The unit tests need **no scanners installed**. Parsers are tested against real tool output
captured in `tests/fixtures/`, and the CLI tests use `--import`.

To run the real scanners, build the image:

```bash
docker build -t breachgraph:dev .
docker run --rm -v "$PWD:/src" breachgraph:dev scan examples/vulnerable-app --keep-raw -o .tmp/demo
```

`--keep-raw` saves each scanner's raw JSON in `.tmp/demo/raw/`. That is how fixtures are captured.

## Pull requests

- Keep PRs focused, and add or update tests for any behavior change.
- `ruff format`, `ruff check` and `mypy --strict` must pass (CI enforces them).
- Update `CHANGELOG.md` under *Unreleased*.
- New scanner adapters: follow [docs/architecture.md](docs/architecture.md#adding-a-scanner),
  and pin plus checksum the binary in the `Dockerfile`.

## Bumping a bundled scanner

1. Pick a release that is at least two weeks old.
2. Update the version and **both** SHA-256 values (amd64 and arm64) in the `Dockerfile`, using
   the checksums file published with that release.
3. Run the `docker` CI job. It scans the demo app end to end.

## Releasing (maintainers)

1. Update `version` in `pyproject.toml` and `CHANGELOG.md`.
2. Tag `vX.Y.Z` and push the tag. The release workflow publishes the image, PyPI package and
   GitHub release, and moves the `vX` tag.
