"""Path normalization and gitignore-style glob matching (``**`` aware, POSIX separators)."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path


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


_PROBE = "\x00probe"  # a name no real pattern targets: matches only patterns covering a whole directory


def iter_files(root: Path, exclude: list[str]) -> Iterator[tuple[Path, str]]:
    """(path, repo-relative POSIX path) of every file under ``root`` that ``exclude`` keeps.

    Excluded directories (and .git) are pruned instead of walked, which matters for .venv and
    node_modules: walking them first is what made scans slow. A symlink is followed only when it
    stays inside ``root``: the repository is untrusted, and a link to ~/.aws/credentials must not
    be read (directory links are never walked)."""
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        rel_dir = normalize_path(base.relative_to(root).as_posix()) if base != root else ""
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d != ".git" and not matches_any(f"{rel_dir}/{d}/{_PROBE}".lstrip("/"), exclude)
        )
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}".lstrip("/")
            path = base / name
            # is_file() is False for broken symlinks and sockets, which would fail a later stat().
            if matches_any(rel, exclude) or not path.is_file():
                continue
            if path.is_symlink() and not path.resolve().is_relative_to(real_root):
                continue
            yield path, rel


def project_name(target: Path, explicit: str | None = None) -> str:
    """What reports call the scanned project: an explicit name, else the git remote's repository
    name (plus the subdirectory scanned), else the directory name. Inside the Docker image the
    repository is mounted at /src, so the directory name alone would call every project "src"."""
    if explicit:
        return explicit

    def git(*args: str) -> str:
        try:
            proc = subprocess.run(
                ["git", "-C", str(target), *args], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return proc.stdout.strip() if proc.returncode == 0 else ""

    url = git("config", "--get", "remote.origin.url")
    name = re.sub(r"\.git$", "", url.rstrip("/")).rsplit("/", 1)[-1].rsplit(":", 1)[-1] if url else ""
    if not name and (repo := os.environ.get("GITHUB_REPOSITORY")):
        name = repo.rsplit("/", 1)[-1]
    if not name:
        return target.resolve().name or str(target)
    sub = git("rev-parse", "--show-prefix").rstrip("/")
    return f"{name}/{sub}" if sub else name
