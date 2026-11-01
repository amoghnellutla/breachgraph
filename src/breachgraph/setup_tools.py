"""`breachgraph setup`: every scanner in the cache directory, without Docker.

A `pip install breachgraph` alone runs only what is already on the machine, so a first scan
misses most of what the tool can do. This installs the same versions the Docker image pins: the
binaries from their releases, each checked against a SHA-256 recorded in pins.json before it is
unpacked, and the Python scanners into their own virtual environments from the hash-pinned locks.
Nothing goes outside the cache directory, and no code from a download runs during setup.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

import httpx

from breachgraph.enrich import cache_dir

PYTHON_TOOLS = ("semgrep", "checkov", "zizmor")
_MAX_DOWNLOAD = 400_000_000


class SetupError(Exception):
    pass


def pins() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(resources.files("breachgraph").joinpath("pins.json").read_text("utf-8"))
    return data


def platform_key() -> str:
    system = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    return f"{system}-{'arm64' if machine in ('arm64', 'aarch64') else 'amd64'}"


def tools_dir() -> Path:
    return cache_dir() / "tools"


def bin_dir() -> Path:
    return tools_dir() / "bin"


def add_to_path() -> None:
    """Put what setup installed on PATH for this process, ahead of nothing the user chose: it goes
    last, so a scanner already installed on the machine keeps being the one that runs."""
    dirs = [bin_dir()]
    dirs += [tools_dir() / n / ("Scripts" if os.name == "nt" else "bin") for n in PYTHON_TOOLS]
    found = [str(d) for d in dirs if d.is_dir()]
    if found:
        os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", ""), *found])


def _download(url: str) -> bytes:
    with httpx.stream("GET", url, follow_redirects=True, timeout=120) as resp:
        resp.raise_for_status()
        data = bytearray()
        for chunk in resp.iter_bytes():
            data += chunk
            if len(data) > _MAX_DOWNLOAD:
                raise SetupError(f"{url} is larger than expected")
    return bytes(data)


def _unpack(data: bytes, name: str, member: str) -> bytes:
    """Read one named file from an archive; nothing else in it is touched."""
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            match = next((n for n in zf.namelist() if n.rsplit("/", 1)[-1] == member), None)
            if match is None:
                raise SetupError(f"{member} is not in {name}")
            return zf.read(match)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for info in tf.getmembers():
            if info.isfile() and info.name.rsplit("/", 1)[-1] == member:
                handle = tf.extractfile(info)
                if handle is not None:
                    return handle.read()
    raise SetupError(f"{member} is not in {name}")


def install_binary(tool: str, spec: dict[str, Any], key: str) -> Path:
    asset = spec["files"].get(key)
    if asset is None:
        raise SetupError(f"{tool} {spec['version']} has no build for {key}")
    data = _download(asset["url"])
    actual = hashlib.sha256(data).hexdigest()
    if actual != asset["sha256"]:
        raise SetupError(f"{tool}: checksum mismatch (expected {asset['sha256']}, got {actual})")
    member = tool + (".exe" if key.startswith("windows") else "")
    dest = bin_dir() / member
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(_unpack(data, asset["url"].rsplit("/", 1)[-1], member))
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def install_python(tool: str) -> Path:
    venv = tools_dir() / tool
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
    with resources.as_file(resources.files("breachgraph").joinpath(f"locks/{tool}.txt")) as lock:
        proc = subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet", "--require-hashes", "-r", str(lock)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    if proc.returncode != 0:
        raise SetupError(f"{tool}: pip failed: {proc.stderr.strip()[-400:]}")
    return venv


def targets() -> list[str]:
    return [*pins()["binaries"], *PYTHON_TOOLS]
