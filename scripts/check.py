"""Run the CI checks (format, lint, types, tests) and print one line per passing step.

Failing steps print only their relevant output, so the result is short either way.

    python scripts/check.py            # everything, like CI
    python scripts/check.py --fix      # apply ruff format and ruff --fix first
    python scripts/check.py -k ai      # only tests matching "ai" (lint and types still run)
    python scripts/check.py --fast     # skip mypy
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_LINES = 60


def run(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def tail(text: str) -> str:
    lines = text.splitlines()
    if len(lines) <= MAX_LINES:
        return text
    return f"... ({len(lines) - MAX_LINES} lines cut)\n" + "\n".join(lines[-MAX_LINES:])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fix", action="store_true", help="run ruff format and ruff check --fix first")
    ap.add_argument("--fast", action="store_true", help="skip mypy")
    ap.add_argument("-k", help="pytest -k expression")
    opts = ap.parse_args()

    if opts.fix:
        run(["ruff", "format", "src", "tests", "scripts"])
        run(["ruff", "check", "--fix", "--quiet", "src", "tests", "scripts"])

    # pyproject's addopts already has -q; a second -q would hide the "N passed" line.
    pytest = ["pytest", "--no-header", "-p", "no:cacheprovider", "--tb=short", "-rfE"]
    if opts.k:
        pytest += ["-k", opts.k]
    steps: list[tuple[str, list[str]]] = [
        ("format", ["ruff", "format", "--check", "--quiet", "src", "tests", "scripts"]),
        ("lint", ["ruff", "check", "--quiet", "src", "tests", "scripts"]),
    ]
    if not opts.fast:
        steps.append(("types", ["mypy"]))
    steps.append(("tests", pytest))

    failed = 0
    for name, args in steps:
        start = time.monotonic()
        code, out = run(args)
        secs = f"{time.monotonic() - start:.0f}s"
        if name == "tests":
            summary = next(
                (ln for ln in reversed(out.splitlines()) if re.search(r"passed|failed|error", ln)), ""
            )
            if code == 0:
                print(f"ok    tests  {summary.strip('= ')} ({secs})")
                continue
            # Drop the progress dots; keep the failure details and the short summary.
            body = "\n".join(
                ln for ln in out.splitlines() if not re.fullmatch(r"[.sxFE]+\s*(\[\s*\d+%\])?", ln)
            )
            print(f"FAIL  tests  {summary.strip('= ')} ({secs})\n{tail(body)}")
        elif code == 0:
            print(f"ok    {name} ({secs})")
            continue
        else:
            hint = "  (try --fix)" if name in ("format", "lint") else ""
            print(f"FAIL  {name}{hint}\n{tail(out)}")
        failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
