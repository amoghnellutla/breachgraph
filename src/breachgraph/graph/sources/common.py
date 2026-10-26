"""Shared helpers for configuration parsers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from breachgraph.paths import iter_files, normalize_path

MAX_FILE_BYTES = 2_000_000


@dataclass
class SourceContext:
    root: Path
    exclude: list[str]
    # Things we saw but could not analyze. Reported so users know the graph's blind spots.
    skipped: list[str] = field(default_factory=list)

    def rel(self, path: Path) -> str:
        return normalize_path(path.relative_to(self.root).as_posix())

    def files(self, *suffixes: str) -> Iterator[Path]:
        for path, _rel in iter_files(self.root, self.exclude):
            if path.suffix.lower() in suffixes and path.stat().st_size <= MAX_FILE_BYTES:
                yield path

    def read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self.skipped.append(f"{self.rel(path)}: unreadable")
            return None


def line_of(text: str, needle: str, start: int = 0) -> int | None:
    """1-based line of the first occurrence of ``needle`` at or after char offset ``start``."""
    idx = text.find(needle, start)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else None
