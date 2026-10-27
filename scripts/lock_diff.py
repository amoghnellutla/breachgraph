"""Summarize how the requirement locks changed against git HEAD, one line per package.

python scripts/lock_diff.py   # e.g. "semgrep 1.179.0 -> 1.180.0 (semgrep.txt)"
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def pins(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if m := _PIN.match(line):
            out[m.group(1).lower()] = m.group(2)
    return out


def changes(old: str, new: str) -> list[str]:
    before, after = pins(old), pins(new)
    lines = []
    for name in sorted(set(before) | set(after)):
        a, b = before.get(name), after.get(name)
        if a != b:
            lines.append(f"{name} {a or '(new)'} -> {b or '(removed)'}")
    return lines


def main() -> int:
    for lock in sorted((ROOT / "requirements").glob("*.txt")):
        rel = lock.relative_to(ROOT).as_posix()
        old = subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:{rel}"], capture_output=True, text=True)
        for line in changes(old.stdout if old.returncode == 0 else "", lock.read_text(encoding="utf-8")):
            print(f"{line} ({lock.name})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
