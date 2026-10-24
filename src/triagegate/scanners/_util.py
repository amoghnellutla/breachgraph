from __future__ import annotations

import re
from pathlib import Path

from triagegate.paths import normalize_path

_MAX_SNIPPET_LINES = 12


def read_snippet(target: Path, rel_path: str, start: int | None, end: int | None) -> str | None:
    """Read source lines from disk. Used instead of the tools' own snippets, which are
    sometimes redacted or replaced (e.g. Semgrep's "requires login")."""
    if not start:
        return None
    path = (target / normalize_path(rel_path)).resolve()
    try:
        path.relative_to(target.resolve())  # never read outside the scanned tree
        with path.open(encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return None
    stop = min(end or start, start + _MAX_SNIPPET_LINES - 1)
    chunk = lines[start - 1 : stop]
    return "\n".join(chunk) if chunk else None


def first_sentence(text: str, limit: int = 140) -> str:
    text = " ".join(text.split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    sentence = m.group(1) if m else text
    return sentence if len(sentence) <= limit else sentence[: limit - 1].rstrip() + "…"


def simple_dir_excludes(patterns: list[str]) -> list[str]:
    """Reduce triagegate globs to wildcard-free names/paths ("node_modules", "examples/demo") that
    every tool's CLI understands, so excluded trees are not scanned at all. Anything more complex
    is still enforced afterwards by triagegate's own filtering."""
    out: list[str] = []
    for p in patterns:
        name = p.strip("/").removeprefix("**/")
        if name and not any(ch in name for ch in "*?["):
            out.append(name)
    return out
