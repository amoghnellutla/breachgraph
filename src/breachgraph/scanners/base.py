"""Scanner adapter interface. One file per tool; implement ``commands`` and ``parse``."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from breachgraph.config import Config, ScannerConfig
from breachgraph.models import Finding, ToolRun, ToolStatus


class ScannerError(Exception):
    pass


@dataclass
class ScanContext:
    target: Path  # absolute path of the directory being scanned
    work_dir: Path  # scratch dir for raw tool output
    config: Config
    artifacts: dict[str, str] = field(default_factory=dict)
    files: list[str] | None = None  # incremental scan: only these repo-relative files


@dataclass
class Step:
    cmd: list[str]
    output: Path  # file the tool writes; must exist after the command
    parse: bool = True  # False for side artifacts like an SBOM
    stdout_to_output: bool = False  # tool prints its report to stdout instead of a file


@dataclass
class ScannerOutcome:
    run: ToolRun
    findings: list[Finding] = field(default_factory=list)


class Scanner(ABC):
    name: ClassVar[str]
    binary: ClassVar[str]
    version_args: ClassVar[list[str]] = ["--version"]

    def settings(self, config: Config) -> ScannerConfig:
        result: ScannerConfig = getattr(config.scanners, self.name)
        return result

    def enabled(self, config: Config) -> bool:
        return self.settings(config).enabled

    def executable(self) -> str | None:
        override = os.environ.get(f"BREACHGRAPH_{self.name.upper()}_BIN")
        return override or shutil.which(self.binary)

    def is_available(self) -> bool:
        return self.executable() is not None

    def version(self) -> str | None:
        exe = self.executable()
        if not exe:
            return None
        try:
            proc = subprocess.run(
                [exe, *self.version_args], capture_output=True, text=True, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = (proc.stdout or proc.stderr).strip()
        m = re.search(r"\d+\.\d+(?:\.\d+)?", text)
        if m:
            return m.group(0)
        return text.splitlines()[0] if text else None

    @abstractmethod
    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        """Commands to run. Append ``self.settings(ctx.config).extra_args`` where it belongs."""

    @abstractmethod
    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        """Turn the tool's decoded JSON into Findings."""

    def accept_exit(self, code: int) -> bool:
        # Most scanners exit non-zero when they find something; the output file is the truth.
        return code in (0, 1)

    def run(self, ctx: ScanContext) -> ScannerOutcome:
        started = time.monotonic()
        exe = self.executable()
        if exe is None:
            return ScannerOutcome(
                ToolRun(
                    name=self.name,
                    status=ToolStatus.SKIPPED,
                    message=f"{self.binary} not found on PATH",
                )
            )
        settings = self.settings(ctx.config)
        timeout = settings.timeout or ctx.config.timeout
        findings: list[Finding] = []
        try:
            for step in self.steps(ctx, exe):
                step.output.unlink(missing_ok=True)
                proc = subprocess.run(
                    step.cmd,
                    cwd=ctx.target,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=False,
                )
                if step.stdout_to_output and proc.stdout:
                    step.output.write_text(proc.stdout, encoding="utf-8")
                if not self.accept_exit(proc.returncode) or not step.output.exists():
                    tail = (proc.stderr or proc.stdout or "").strip()[-1500:]
                    raise ScannerError(f"exit code {proc.returncode}: {tail}")
                if step.parse:
                    findings.extend(self.parse(load_json(step.output), ctx))
        except subprocess.TimeoutExpired:
            return self._failed(started, f"timed out after {timeout}s")
        except (ScannerError, OSError, ValueError) as exc:
            return self._failed(started, str(exc))
        return ScannerOutcome(
            ToolRun(
                name=self.name,
                status=ToolStatus.OK,
                version=self.version(),
                duration_s=round(time.monotonic() - started, 2),
                findings=len(findings),
            ),
            findings,
        )

    def import_file(self, path: Path, ctx: ScanContext) -> ScannerOutcome:
        """Ingest a report the tool produced elsewhere (e.g. an earlier CI step)."""
        findings = self.parse(load_json(path), ctx)
        return ScannerOutcome(
            ToolRun(
                name=self.name,
                status=ToolStatus.IMPORTED,
                findings=len(findings),
                message=f"imported from {path.name}",
            ),
            findings,
        )

    def _failed(self, started: float, message: str) -> ScannerOutcome:
        return ScannerOutcome(
            ToolRun(
                name=self.name,
                status=ToolStatus.FAILED,
                duration_s=round(time.monotonic() - started, 2),
                message=message,
            )
        )


def load_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name} is not valid JSON: {exc}") from exc


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
