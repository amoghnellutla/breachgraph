"""Extract imported module/package names from source files, per language, with tree-sitter.

We record, for each first-party file, the set of top-level imported names and, where the language
makes it cheap, which other first-party modules it imports (for entry-point reachability).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import tree_sitter as ts
import tree_sitter_go as ts_go
import tree_sitter_java as ts_java
import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts

from breachgraph.graph.sources.common import SourceContext

_LANGS = {
    ".py": ("python", ts_py.language()),
    ".js": ("js", ts_js.language()),
    ".mjs": ("js", ts_js.language()),
    ".cjs": ("js", ts_js.language()),
    ".jsx": ("js", ts_js.language()),
    ".ts": ("js", ts_ts.language_typescript()),
    ".tsx": ("js", ts_ts.language_tsx()),
    ".java": ("java", ts_java.language()),
    ".go": ("go", ts_go.language()),
}
_PARSERS: dict[str, ts.Parser] = {}


@dataclass
class FileImports:
    path: str
    lang: str
    externals: set[str] = field(default_factory=set)  # third-party top-level names
    local: set[str] = field(default_factory=set)  # relative/first-party import targets (resolved paths)


@dataclass
class ImportIndex:
    files: dict[str, FileImports] = field(default_factory=dict)

    def external_to_files(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for fi in self.files.values():
            for name in fi.externals:
                out.setdefault(name, set()).add(fi.path)
        return out


def _parser(suffix: str) -> ts.Parser:
    if suffix not in _PARSERS:
        _PARSERS[suffix] = ts.Parser(ts.Language(_LANGS[suffix][1]))
    return _PARSERS[suffix]


def _text(n: ts.Node | None) -> str:
    return n.text.decode("utf-8", "replace") if n is not None and n.text else ""


def collect_imports(ctx: SourceContext) -> ImportIndex:
    index = ImportIndex()
    for path in ctx.files(*_LANGS):
        data = path.read_bytes()
        if b"\0" in data[:1024]:
            continue
        rel = ctx.rel(path)
        lang = _LANGS[path.suffix.lower()][0]
        try:
            tree = _parser(path.suffix.lower()).parse(data)
        except (ValueError, RecursionError):  # unparseable file, skip
            continue
        fi = FileImports(path=rel, lang=lang)
        {"python": _py, "js": _js, "java": _java, "go": _go}[lang](tree.root_node, fi, rel)
        index.files[rel] = fi
    return index


def _py(root: ts.Node, fi: FileImports, rel: str) -> None:
    for n in _iter(root):
        if n.type == "import_statement":
            for name in n.children:
                if name.type in ("dotted_name", "aliased_import"):
                    top = _text(name).split(" as ")[0].strip().split(".")[0]
                    if top:
                        fi.externals.add(top)
        elif n.type == "import_from_statement":
            mod = n.child_by_field_name("module_name")
            text = _text(mod)
            if text.startswith("."):  # relative -> first-party
                fi.local.add(_resolve_py_relative(rel, text))
            elif text:
                fi.externals.add(text.split(".")[0])


def _resolve_py_relative(rel: str, dotted: str) -> str:
    base = PurePosixPath(rel).parent
    ups = len(dotted) - len(dotted.lstrip("."))
    for _ in range(ups - 1):
        base = base.parent
    tail = dotted.lstrip(".").replace(".", "/")
    return str(base / tail) if tail else str(base)


_JS_IMPORT = re.compile(r"""(?:import\b[^'"]*from\s*|require\(\s*|import\(\s*)['"]([^'"]+)['"]""")


def _js(root: ts.Node, fi: FileImports, rel: str) -> None:
    # Regex over source is robust across the many JS/TS import forms; tree-sitter parse already
    # validated it is code. Node text is the whole file here.
    src = _text(root)
    for m in _JS_IMPORT.finditer(src):
        spec = m.group(1)
        if spec.startswith("."):
            fi.local.add(_resolve_js_relative(rel, spec))
        else:
            parts = spec.split("/")
            top = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
            fi.externals.add(top)


def _resolve_js_relative(rel: str, spec: str) -> str:
    base = PurePosixPath(rel).parent
    target = (base / spec).as_posix()
    return re.sub(r"\.(js|ts|jsx|tsx|mjs|cjs)$", "", target).rstrip("/")


def _java(root: ts.Node, fi: FileImports, rel: str) -> None:
    for n in _iter(root):
        if n.type == "import_declaration":
            text = _text(n).removeprefix("import").removeprefix("static").strip().rstrip(";").strip()
            # Group-id-ish: first two package segments (com.fasterxml -> com.fasterxml)
            segs = text.split(".")
            if len(segs) >= 2:
                fi.externals.add(".".join(segs[:2]))
                fi.externals.add(segs[0])


def _go(root: ts.Node, fi: FileImports, rel: str) -> None:
    for n in _iter(root):
        if n.type == "import_spec":
            path = _text(n.child_by_field_name("path")).strip('"')
            if path:
                fi.externals.add(path)  # full module path, e.g. github.com/gin-gonic/gin


def _iter(node: ts.Node):  # type: ignore[no-untyped-def]
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)
