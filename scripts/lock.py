"""Regenerate the hash-pinned requirement files in requirements/ (needs Docker).

    python scripts/lock.py             # re-resolve within the pins in *.in and pyproject.toml
    python scripts/lock.py --upgrade   # take the newest allowed versions

The Docker image and CI install only from these files with --require-hashes, so every Python
package that ends up in a release is fixed by hash. Resolution is universal (any platform), which
keeps the multi-arch image build on the same set. uv runs from an image pinned by digest.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UV = (
    "ghcr.io/astral-sh/uv:0.13.4-python3.12-trixie-slim"
    "@sha256:0d42b7b065ada5139af940bf3fb178b926675450e786badc854c9f73736cc6c4"
)
# output file -> uv pip compile arguments
LOCKS = {
    "semgrep.txt": ["requirements/semgrep.in"],
    "checkov.txt": ["requirements/checkov.in"],
    "zizmor.txt": ["requirements/zizmor.in"],
    "tools.txt": ["requirements/tools.in"],
    "runtime.txt": ["pyproject.toml", "--extra", "ai"],
    "dev.txt": ["pyproject.toml", "--extra", "dev"],
}


def main() -> int:
    upgrade = ["--upgrade"] if "--upgrade" in sys.argv[1:] else []
    for out, args in LOCKS.items():
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/w",
            "-w",
            "/w",
            UV,
            "uv",
            "pip",
            "compile",
            *args,
            "--universal",
            "--python-version",
            "3.11",
            "--generate-hashes",
            "--no-header",
            "--quiet",
            *upgrade,
            "-o",
            f"requirements/{out}",
        ]
        print("lock", out, flush=True)
        if subprocess.run(cmd, check=False).returncode:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
