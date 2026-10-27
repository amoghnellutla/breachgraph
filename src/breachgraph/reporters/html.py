"""Single-file HTML report (no external assets, works offline, safe to attach to CI artifacts)."""

from __future__ import annotations

import json
from pathlib import PurePath
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from breachgraph.compare import path_changes
from breachgraph.graph.attack import TECHNIQUES, technique_url
from breachgraph.models import ScanResult, Status

# Autoescape is enabled for every template; scanner output is untrusted.
_env = Environment(  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    loader=PackageLoader("breachgraph.reporters", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.globals.update(attack_name=lambda t: TECHNIQUES.get(t, t), attack_url=technique_url)


def explorer_payload(result: ScanResult) -> dict[str, Any] | None:
    """What the interactive attack-graph explorer draws: the nodes and edges paths run through."""
    ag = result.attack_graph
    if ag is None or not ag.paths or ag.graph is None:
        return None
    return {
        "nodes": [n.model_dump(mode="json") for n in ag.graph.nodes],
        "edges": [e.model_dump(mode="json") for e in ag.graph.edges],
        "truncated": ag.graph.truncated,
        "paths": [
            {
                "id": p.id or str(i),
                "target": p.target,
                "confidence": p.confidence,
                "gating": p.gating,
                "is_new": p.is_new,
                "score": p.score,
                "nodes": p.node_ids,
                "weaknesses": p.weaknesses,
                "steps": [
                    {"via": s.via, "title": s.weakness_title, "at": _at(s.evidence_path, s.evidence_line)}
                    for s in p.steps
                ],
            }
            for i, p in enumerate(ag.paths)
        ],
        "fixes": [
            {
                "fingerprint": c.fingerprint,
                "title": c.title,
                "weakness": c.weakness,
                "paths_cut": c.paths_cut,
                "at": _at(c.path, c.line),
            }
            for c in ag.choke_points
            if c.fingerprint
        ],
    }


def _at(path: str | None, line: int | None) -> str | None:
    return f"{path}:{line}" if path and line else path


def _embed(payload: dict[str, Any] | None) -> Markup:
    """JSON for a <script type="application/json"> block. <, > and & are escaped so repository
    content (node names, notes) can never close the script element."""
    text = json.dumps(payload, separators=(",", ":"))
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return Markup(text)  # noqa: S704  (escaped above; only ever placed in a JSON script block)


def render(result: ScanResult) -> str:
    open_by_prio: dict[str, int] = {}
    for f in result.findings:
        if f.status is not Status.SUPPRESSED:
            open_by_prio[f.priority.value] = open_by_prio.get(f.priority.value, 0) + 1
    payload = explorer_payload(result)
    return _env.get_template("report.html.j2").render(
        result=result,
        target_name=PurePath(result.target).name or result.target,
        open_by_prio=open_by_prio,
        gating=sum(1 for f in result.findings if f.gating),
        suppressed=sum(1 for f in result.findings if f.status is Status.SUPPRESSED),
        tools=sorted({s for f in result.findings for s in f.sources}),
        categories=sorted({f.category.value for f in result.findings}),
        changes=path_changes(result),
        explorer=payload,
        explorer_json=_embed(payload),
    )
