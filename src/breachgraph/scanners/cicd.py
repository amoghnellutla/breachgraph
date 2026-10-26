"""breachgraph's own CI/CD and supply-chain checks (see breachgraph.cicd). Runs in-process."""

from __future__ import annotations

import time
from typing import Any, ClassVar

from breachgraph import __version__
from breachgraph.cicd import analyze
from breachgraph.models import Finding, ToolRun, ToolStatus
from breachgraph.scanners.base import ScanContext, Scanner, ScannerOutcome, Step


class CicdScanner(Scanner):
    name: ClassVar[str] = "cicd"
    binary: ClassVar[str] = "builtin"

    def executable(self) -> str | None:
        return "builtin"

    def version(self) -> str | None:
        return __version__

    def steps(self, ctx: ScanContext, exe: str) -> list[Step]:
        return []

    def parse(self, raw: Any, ctx: ScanContext) -> list[Finding]:
        return []

    def run(self, ctx: ScanContext) -> ScannerOutcome:
        started = time.monotonic()
        try:
            findings, skipped = analyze(ctx.target, ctx.config.exclude_paths)
        except OSError as exc:
            return self._failed(started, str(exc))
        return ScannerOutcome(
            ToolRun(
                name=self.name,
                status=ToolStatus.OK,
                version=__version__,
                duration_s=round(time.monotonic() - started, 2),
                findings=len(findings),
                message="; ".join(skipped[:3]) or None,
            ),
            findings,
        )
