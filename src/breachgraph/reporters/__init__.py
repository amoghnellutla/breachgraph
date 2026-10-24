"""Output writers. Every format is rendered from the same ScanResult."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from breachgraph.models import ScanResult
from breachgraph.reporters import html, junit, markdown, sarif


def _json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def _sarif(result: ScanResult) -> str:
    return json.dumps(sarif.build(result), indent=2)


FORMATS: dict[str, tuple[str, Callable[[ScanResult], str]]] = {
    "json": ("breachgraph.json", _json),
    "sarif": ("breachgraph.sarif", _sarif),
    "html": ("breachgraph.html", html.render),
    "md": ("breachgraph.md", markdown.render),
    "junit": ("breachgraph-junit.xml", junit.render),
}


def write_reports(result: ScanResult, out_dir: Path, formats: list[str]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for fmt in formats:
        filename, render = FORMATS[fmt]
        path = out_dir / filename
        path.write_text(render(result), encoding="utf-8")
        written[fmt] = path
    return written
