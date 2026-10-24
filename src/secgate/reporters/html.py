"""Single-file HTML report (no external assets, works offline, safe to attach to CI artifacts)."""

from __future__ import annotations

from pathlib import PurePath

from jinja2 import Environment, PackageLoader, select_autoescape

from secgate.models import ScanResult, Status

# Autoescape is enabled for every template; scanner output is untrusted.
_env = Environment(  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    loader=PackageLoader("secgate.reporters", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(result: ScanResult) -> str:
    open_by_prio: dict[str, int] = {}
    for f in result.findings:
        if f.status is not Status.SUPPRESSED:
            open_by_prio[f.priority.value] = open_by_prio.get(f.priority.value, 0) + 1
    return _env.get_template("report.html.j2").render(
        result=result,
        target_name=PurePath(result.target).name or result.target,
        open_by_prio=open_by_prio,
        gating=sum(1 for f in result.findings if f.gating),
        suppressed=sum(1 for f in result.findings if f.status is Status.SUPPRESSED),
        tools=sorted({s for f in result.findings for s in f.sources}),
        categories=sorted({f.category.value for f in result.findings}),
    )
