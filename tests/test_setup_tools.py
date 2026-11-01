"""`breachgraph setup` installs what the Dockerfile pins, and refuses anything else."""

import hashlib
import io
import os
import re
import tarfile
from pathlib import Path

import pytest

from breachgraph import setup_tools as tools

ROOT = Path(__file__).parent.parent


def archive(member: str, body: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tf:
        info = tarfile.TarInfo(f"linux-amd64/{member}")
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))
        evil = tarfile.TarInfo("../../evil")
        evil.size = 1
        tf.addfile(evil, io.BytesIO(b"x"))
    return out.getvalue()


def spec(data: bytes, sha: str | None = None) -> dict[str, object]:
    url = "https://example.test/helm.tar.gz"
    return {
        "version": "1",
        "files": {"linux-amd64": {"url": url, "sha256": sha or hashlib.sha256(data).hexdigest()}},
    }


@pytest.fixture(autouse=True)
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("BREACHGRAPH_CACHE_DIR", str(tmp_path))
    return tmp_path


def test_pins_match_the_dockerfile() -> None:
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    pinned = {k.lower(): v for k, v in re.findall(r"^ARG (\w+)_VERSION=(\S+)$", docker, re.M)}
    assert {k: v["version"] for k, v in tools.pins()["binaries"].items()} == pinned


def test_every_platform_has_a_checksum() -> None:
    for spec_ in tools.pins()["binaries"].values():
        assert set(spec_["files"]) == {
            "linux-amd64",
            "linux-arm64",
            "darwin-amd64",
            "darwin-arm64",
            "windows-amd64",
        }
        assert all(re.fullmatch(r"[0-9a-f]{64}", f["sha256"]) for f in spec_["files"].values())


def test_a_verified_binary_is_installed_and_only_that_file(
    monkeypatch: pytest.MonkeyPatch, cache: Path
) -> None:
    data = archive("helm", b"#!/bin/sh\n")
    monkeypatch.setattr(tools, "_download", lambda url: data)
    dest = tools.install_binary("helm", spec(data), "linux-amd64")
    assert dest.read_bytes() == b"#!/bin/sh\n"
    assert not (cache.parent / "evil").exists() and [p.name for p in dest.parent.iterdir()] == ["helm"]


def test_a_tampered_download_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    data = archive("helm", b"tampered")
    monkeypatch.setattr(tools, "_download", lambda url: data)
    with pytest.raises(tools.SetupError, match="checksum mismatch"):
        tools.install_binary("helm", spec(data, "0" * 64), "linux-amd64")
    assert not tools.bin_dir().exists()


def test_an_unsupported_platform_says_so() -> None:
    with pytest.raises(tools.SetupError, match="no build for"):
        tools.install_binary("helm", spec(b""), "plan9-amd64")


def test_installed_tools_come_after_what_the_user_has(monkeypatch: pytest.MonkeyPatch) -> None:
    tools.bin_dir().mkdir(parents=True)
    monkeypatch.setenv("PATH", "first")
    tools.add_to_path()
    assert os.environ["PATH"].split(os.pathsep) == ["first", str(tools.bin_dir())]


def test_locks_resolve_from_a_source_checkout() -> None:
    for tool in tools.PYTHON_TOOLS:
        assert tools.lock_file(tool).is_file()
