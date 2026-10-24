"""Path normalization and gitignore-style glob matching (``**`` aware, POSIX separators)."""

from __future__ import annotations

import re
from functools import lru_cache


def normalize_path(path: str) -> str:
    """Return a repo-relative POSIX path: backslashes -> '/', no leading './' or '/'."""
    if path.startswith(("http://", "https://")):
        return path
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    pat = normalize_path(pattern)
    # A pattern without a slash matches at any depth, like .gitignore.
    if "/" not in pat.rstrip("/"):
        pat = "**/" + pat
    if pat.endswith("/"):
        pat += "**"
    i, out = 0, []
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    # A pattern naming a directory also matches everything below it.
    return re.compile("^" + "".join(out) + "(?:/.*)?$")


def glob_match(path: str, pattern: str) -> bool:
    return bool(_compile(pattern).match(normalize_path(path)))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(glob_match(path, p) for p in patterns)
