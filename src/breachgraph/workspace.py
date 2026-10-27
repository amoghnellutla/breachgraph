"""Scan several repositories as one: `breachgraph scan app/ infra/`.

Small companies often keep application code and its Terraform or Kubernetes in separate
repositories, and an attack path crosses both. The repositories are laid out side by side in one
temporary workspace (app/..., infra/...), hard-linked where possible so nothing is copied, and
scanned as a single target. Graph nodes are named after resources, not files, so the image built
in one repository links to the Deployment that runs it in the other.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from breachgraph.paths import iter_files, project_name


def labels(roots: list[Path]) -> list[str]:
    """A unique, readable folder name per repository."""
    out: list[str] = []
    for root in roots:
        base = re.sub(r"[^\w.-]+", "-", project_name(root).split("/")[-1]) or "repo"
        name, n = base, 2
        while name in out:
            name, n = f"{base}-{n}", n + 1
        out.append(name)
    return out


def build(roots: list[Path], exclude: list[str], dest: Path) -> dict[str, Path]:
    """Lay the repositories out under ``dest``; returns {folder: repository root}."""
    mapping = dict(zip(labels(roots), roots, strict=True))
    for label, root in mapping.items():
        for path, rel in iter_files(root, exclude):
            target = dest / label / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(path, target)
            except OSError:  # another filesystem (separate Docker mounts) or no hard links
                shutil.copy2(path, target)
    return mapping
