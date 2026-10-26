"""GitHub Actions workflow files, parsed with the line numbers of every job and step.

Scalars are kept as strings (``on`` stays "on" instead of YAML 1.1's ``True``), which is all the
analysis needs and keeps expressions exactly as written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from breachgraph.paths import iter_files

_MAX_BYTES = 1_000_000
SECRET_RE = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")


@dataclass
class Step:
    index: int
    line: int
    end_line: int
    name: str = ""
    uses: str = ""
    run: str = ""
    run_line: int = 0  # line where the run script starts
    with_: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    if_: str = ""

    @property
    def action(self) -> str:
        """`actions/checkout` for `actions/checkout@v4`, lowercased."""
        return self.uses.split("@", 1)[0].lower()


@dataclass
class Job:
    id: str
    line: int
    end_line: int
    if_: str = ""
    permissions: Any = None  # None = not set at job level
    environment: str = ""
    env: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    uses: str = ""  # reusable workflow call
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    path: str  # repo-relative
    name: str
    triggers: set[str]
    permissions: Any
    jobs: list[Job]
    env: dict[str, Any] = field(default_factory=dict)

    def job_permissions(self, job: Job) -> Any:
        """Effective GITHUB_TOKEN permissions; None means the repository default applies."""
        return job.permissions if job.permissions is not None else self.permissions


def _py(node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        return {str(_py(k)): _py(v) for k, v in node.value}
    if isinstance(node, yaml.SequenceNode):
        return [_py(x) for x in node.value]
    return node.value


def _child(node: yaml.Node | None, key: str) -> yaml.Node | None:
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode) and k.value == key:
                child: yaml.Node = v
                return child
    return None


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _triggers(on: Any) -> set[str]:
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return set(on)
    return set()


def parse_workflow(text: str, rel: str) -> Workflow | None:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return None
    if not isinstance(root, yaml.MappingNode):
        return None
    data = _py(root)
    jobs_node = _child(root, "jobs")
    jobs: list[Job] = []
    if isinstance(jobs_node, yaml.MappingNode):
        for key_node, job_node in jobs_node.value:
            body = _dict(_py(job_node))
            job = Job(
                id=str(key_node.value),
                line=key_node.start_mark.line + 1,
                end_line=job_node.end_mark.line + (0 if job_node.end_mark.column == 0 else 1),
                if_=_str(body.get("if")),
                permissions=body.get("permissions"),
                environment=_str(body.get("environment")) or _str(_dict(body.get("environment")).get("name")),
                env=_dict(body.get("env")),
                uses=_str(body.get("uses")),
                raw=body,
            )
            steps_node = _child(job_node, "steps")
            if isinstance(steps_node, yaml.SequenceNode):
                for i, s_node in enumerate(steps_node.value):
                    s = _dict(_py(s_node))
                    run_node = _child(s_node, "run")
                    job.steps.append(
                        Step(
                            index=i,
                            line=s_node.start_mark.line + 1,
                            end_line=s_node.end_mark.line + (0 if s_node.end_mark.column == 0 else 1),
                            name=_str(s.get("name")),
                            uses=_str(s.get("uses")),
                            run=_str(s.get("run")),
                            run_line=(run_node.start_mark.line + 1) if run_node is not None else 0,
                            with_=_dict(s.get("with")),
                            env=_dict(s.get("env")),
                            if_=_str(s.get("if")),
                        )
                    )
            jobs.append(job)
    return Workflow(
        path=rel,
        name=_str(data.get("name")) or rel.rsplit("/", 1)[-1],
        triggers=_triggers(data.get("on")),
        permissions=data.get("permissions"),
        jobs=jobs,
        env=_dict(data.get("env")),
    )


def load_workflows(root: Path, exclude: list[str]) -> tuple[list[Workflow], list[str]]:
    """Every workflow under any `.github/workflows/` directory, plus files that failed to parse."""
    found: list[Workflow] = []
    skipped: list[str] = []
    for path, rel in iter_files(root, exclude):
        if path.suffix.lower() not in (".yml", ".yaml") or "/.github/workflows/" not in f"/{rel}":
            continue
        if path.stat().st_size > _MAX_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        wf = parse_workflow(text, rel)
        if wf is None:
            skipped.append(f"{rel}: could not parse workflow YAML")
        else:
            found.append(wf)
    return found, skipped


def job_secrets(wf: Workflow, job: Job) -> dict[str, int]:
    """Repository secrets a job can read -> the line that references each (GITHUB_TOKEN excluded)."""
    names: dict[str, int] = {}
    for step in job.steps:
        for m in SECRET_RE.finditer(repr((step.with_, step.env, step.run))):
            names.setdefault(m.group(1), step.line)
    for m in SECRET_RE.finditer(repr((job.env, wf.env, job.raw.get("with"), job.raw.get("secrets")))):
        names.setdefault(m.group(1), job.line)
    names.pop("GITHUB_TOKEN", None)
    return names
