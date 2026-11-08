"""Single-file HTML report (no external assets, works offline, safe to attach to CI artifacts)."""

from __future__ import annotations

import json
import os
from pathlib import PurePath
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from breachgraph import PROJECT_URL
from breachgraph.compare import path_changes
from breachgraph.graph.attack import TECHNIQUES, technique_url
from breachgraph.models import Finding, ScanResult, Status

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
    at_line = {(f.location.path, f.location.start_line): f for f in result.findings}
    by_fp = {fp: f for f in result.findings for fp in (f.fingerprints or [f.fingerprint])}

    def finding(step: Any) -> Finding | None:
        return at_line.get((step.evidence_path, step.evidence_line)) if step.via else None

    return {
        "nodes": [n.model_dump(mode="json") for n in ag.graph.nodes],
        "edges": [e.model_dump(mode="json") for e in ag.graph.edges],
        "truncated": ag.graph.truncated,
        "smallest": ag.fix_set.fixes if ag.fix_set else [],
        "paths": [
            {
                "id": p.id or str(i),
                "group": p.group or p.id or str(i),
                "known_as": p.known_as,
                "target": p.target,
                "confidence": p.confidence,
                "gating": p.gating,
                "is_new": p.is_new,
                "score": p.score,
                "needs_login": p.needs_login,
                "nodes": p.node_ids,
                "weaknesses": p.weaknesses,
                "steps": [
                    {
                        "via": s.via,
                        "title": s.weakness_title,
                        "at": _at(s.evidence_path, s.evidence_line),
                        "note": s.note,
                        "techniques": s.techniques,
                        "snippet": (found.location.snippet or "")[:600] if (found := finding(s)) else "",
                        "fp": found.fingerprint if found else "",
                    }
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
                "remediation": by_fp[c.fingerprint].remediation if c.fingerprint in by_fp else "",
            }
            for c in ag.choke_points
            if c.fingerprint
        ],
        "patches": result.metadata.get("fix_previews") or [],
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
        target_name=str(result.metadata.get("project") or PurePath(result.target).name or result.target),
        open_by_prio=open_by_prio,
        gating=sum(1 for f in result.findings if f.gating),
        suppressed=sum(1 for f in result.findings if f.status is Status.SUPPRESSED),
        tools=sorted({s for f in result.findings for s in f.sources}),
        categories=sorted({f.category.value for f in result.findings}),
        changes=path_changes(result),
        demo=bool(os.environ.get("BREACHGRAPH_DEMO")),
        project_url=PROJECT_URL,
        explorer=payload,
        explorer_json=_embed(payload),
    )
