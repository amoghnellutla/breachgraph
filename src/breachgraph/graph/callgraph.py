"""Which functions a route handler reaches, across files, so a weakness in a helper counts.

Real handlers delegate: the risky call sits in a service or client module, not in the handler's
own lines. This follows calls by name from the handler, for Python, JavaScript/TypeScript, Java
and Go, with tree-sitter and without type information.

A call resolves only to a function in the same file, the same directory, or a file the caller
imports, so a common method name can't jump across the repository. Anything found this way is
evidence, not proof (dynamic dispatch can miss, a shared name can overreach), so what it links is
medium confidence at most and carries the chain it followed. Files are parsed on demand: a scan
with no weakness outside a handler pays for nothing.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter as ts

from breachgraph.graph.sources.routes import _LANGS, HTTP_METHODS, _text, _walk, parse_tree
from breachgraph.paths import iter_files
from breachgraph.reachability.imports import _JS_IMPORT, _resolve_js_relative, _resolve_py_relative

MAX_DEPTH = 6
MAX_FILES = 3000  # parsed per scan; a repository beyond this keeps handler-only linking
_FAMILY = {".py": "py", ".java": "java", ".go": "go"}  # the rest are JavaScript and TypeScript
_INDEX = re.compile(r"/(?:__init__|index)$")
_NAME = re.compile(r"[A-Za-z_]\w*")
# Function nodes -> the field holding the name.
_FUNCTIONS = {"function_definition", "function_declaration", "method_definition", "method_declaration"}
_CALLS = {"call": "function", "call_expression": "function", "method_invocation": "name"}


@dataclass
class Function:
    file: str
    name: str
    start: int
    end: int
    calls: set[str] = field(default_factory=set)


@dataclass
class _File:
    functions: list[Function]
    imports: set[str]  # module paths, as written: "app/services/fetch", "./client" resolved


def _function_name(node: ts.Node) -> str:
    if node.type in _FUNCTIONS:
        return _text(node.child_by_field_name("name"))
    if node.type in ("arrow_function", "function_expression", "function"):
        own = _text(node.child_by_field_name("name"))
        parent = node.parent  # const fetchUrl = async (u) => {...}
        if own or parent is None:
            return own
        if parent.type in ("variable_declarator", "public_field_definition"):
            return _text(parent.child_by_field_name("name") or parent.child_by_field_name("property"))
        if parent.type == "assignment_expression":  # exports.fetchUrl = function (u) {...}
            names = _NAME.findall(_text(parent.child_by_field_name("left")))
            return names[-1] if names else ""
    return ""


def _called(node: ts.Node) -> str:
    field_name = _CALLS.get(node.type)
    if field_name is None:
        return ""
    names = _NAME.findall(_text(node.child_by_field_name(field_name)))
    return names[-1] if names else ""


def _functions(root: ts.Node, rel: str) -> list[Function]:
    """Each named function with the calls in its body. One walk: a call belongs to the innermost
    named function around it, and an anonymous closure's calls to the function that holds it."""
    out: list[Function] = []
    stack: list[tuple[ts.Node, Function | None]] = [(root, None)]
    while stack:
        node, current = stack.pop()
        if name := _function_name(node):
            current = Function(rel, name, node.start_point[0] + 1, node.end_point[0] + 1)
            out.append(current)
        elif current is not None and (called := _called(node)):
            current.calls.add(called)
        stack.extend((c, current) for c in node.children)
    return out


def _imports(root: ts.Node, rel: str, family: str) -> set[str]:
    out: set[str] = set()
    if family == "js":
        for m in _JS_IMPORT.finditer(_text(root)):
            spec = m.group(1)
            if spec.startswith("."):
                out.add(_resolve_js_relative(rel, spec))
            elif spec[:2] in ("@/", "~/"):  # the usual tsconfig path alias
                out.add(spec[2:])
            else:
                out.add(spec)  # a workspace package, matched by path suffix
        return out
    for n in _walk(root):
        if family == "py" and n.type == "import_statement":
            for c in n.children:
                if c.type in ("dotted_name", "aliased_import"):
                    out.add(_text(c).split(" as ")[0].strip().replace(".", "/"))
        elif family == "py" and n.type == "import_from_statement":
            module = _text(n.child_by_field_name("module_name"))
            base = _resolve_py_relative(rel, module) if module.startswith(".") else module.replace(".", "/")
            out.add(base)
            for c in n.children_by_field_name("name"):
                out.add(posixpath.join(base, _text(c).split(" as ")[0].strip()))
        elif family == "java" and n.type == "import_declaration":
            text = _text(n).removeprefix("import").strip().removeprefix("static").strip().rstrip(";")
            out.add(text.strip().replace(".", "/"))
        elif family == "go" and n.type == "import_spec":
            out.add(_text(n.child_by_field_name("path")).strip('"`'))
    return out


_TAINTED_RULE = re.compile(r"taint|flowing|user[-_ ]?input|request|from-user", re.I)
_ASSIGN = re.compile(
    r"(?:^|[\s;(])(?:const |let |var |final )?([A-Za-z_]\w*)(?:\s*:[^=\n]+)?\s*:?=(?!=)\s*(.+)$"
)
# Called functions, members and Capitalized globals: what a line uses, not the data it reads.
_NOT_DATA = re.compile(r"[A-Za-z_]\w*(?=\s*\()|\.[A-Za-z_]\w*|\b[A-Z]\w*\b|'[^']*'|\"[^\"]*\"")


def _names(code: str) -> set[str]:
    return set(_NAME.findall(_NOT_DATA.sub(" ", code)))


def built_from_constants(lines: list[str], sink: str) -> bool:
    """Whether every value ``sink`` reads is computed from literals in the lines before it: no
    parameter, no request, no outside variable. Any name not assigned there answers False."""
    assigned: dict[str, set[str]] = {}
    for line in lines:
        if m := _ASSIGN.search(line):
            assigned.setdefault(m.group(1), set()).update(_names(m.group(2)))
    pending, seen = _names(sink), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        if name not in assigned:
            return False
        pending |= assigned[name]
    return True


class CallGraph:
    def __init__(self, root: Path, exclude: list[str]) -> None:
        self.root = root
        self.files: dict[str, _File | None] = {}
        self.by_dir: dict[tuple[str, str], list[str]] = {}
        self.by_module: dict[str, list[str]] = {}  # last path segment -> module paths
        self.modules: dict[tuple[str, str], list[str]] = {}
        self.family: dict[str, str] = {}
        for _path, rel in iter_files(root, exclude):
            suffix = posixpath.splitext(rel)[1].lower()
            if suffix not in _LANGS:
                continue
            family = _FAMILY.get(suffix, "js")
            self.family[rel] = family
            self.by_dir.setdefault((family, posixpath.dirname(rel)), []).append(rel)
            module = _INDEX.sub("", posixpath.splitext(rel)[0])
            self.modules.setdefault((family, module), []).append(rel)
            self.by_module.setdefault(posixpath.basename(module), []).append(module)
        self.reached: dict[tuple[str, int, int], dict[tuple[str, int], list[str]]] = {}
        self._visible_of: dict[str, list[str]] = {}
        self._resolved: dict[tuple[str, str], list[Function]] = {}
        self._links: dict[tuple[str, int], list[tuple[int, list[str]]]] | None = None

    def _load(self, rel: str) -> _File | None:
        if rel not in self.files:
            if len(self.files) >= MAX_FILES:
                return None
            info = None
            try:
                tree = parse_tree(self.root / rel)
            except (ValueError, OSError, RecursionError):
                tree = None
            if tree is not None:
                root = tree.root_node
                info = _File(_functions(root, rel), _imports(root, rel, self.family[rel]))
            self.files[rel] = info
        return self.files[rel]

    def _visible(self, rel: str) -> list[str]:
        """The file, its package, and what it imports: where a call in it can land."""
        if rel not in self._visible_of:
            self._load(rel)
            self._visible_of[rel] = self._compute_visible(rel)
        return self._visible_of[rel]

    def _compute_visible(self, rel: str) -> list[str]:
        family = self.family[rel]
        out = [rel, *self.by_dir.get((family, posixpath.dirname(rel)), [])]
        info = self.files.get(rel)
        for spec in info.imports if info else ():
            if family == "go":
                for (fam, d), files in self.by_dir.items():
                    if fam == "go" and d and (spec == d or spec.endswith("/" + d)):
                        out += files
                continue
            exact = self.modules.get((family, spec))
            if exact:
                out += exact
                continue
            for module in self.by_module.get(posixpath.basename(spec), []):
                if module.endswith("/" + spec) or spec.endswith("/" + module):
                    out += self.modules.get((family, module), [])
        return list(dict.fromkeys(out))

    def _resolve(self, rel: str, name: str) -> list[Function]:
        key = (rel, name)
        if key not in self._resolved:
            self._resolved[key] = self._find(rel, name)
        return self._resolved[key]

    def _find(self, rel: str, name: str) -> list[Function]:
        found: list[Function] = []
        for other in self._visible(rel):
            info = self._load(other)
            if info is None:
                continue
            hits = [f for f in info.functions if f.name == name]
            if hits and other == rel:
                return hits  # a local definition shadows the rest
            found += hits
        return found

    def _seeds(self, rel: str, start: int, end: int) -> list[tuple[Function | None, set[str]]]:
        info = self._load(rel)
        if info is None:
            return []
        # Within the route's lines only: a route registered inside start() is not start() itself.
        inside = [f for f in info.functions if start <= f.start and f.end <= end]
        if inside:
            return [(f, f.calls) for f in inside]
        # `router.get("/x", controller.fetch)`: the handler is named on the route's own lines, next
        # to the registration call. An inline closure's calls are on those lines too.
        try:
            lines = (self.root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        return [(None, set(_NAME.findall(" ".join(lines[start - 1 : end]))) - HTTP_METHODS)]

    def reachable(self, rel: str, start: int, end: int) -> dict[tuple[str, int], list[str]]:
        """{(file, function start line): names of the calls leading there} from a handler."""
        key = (rel, start, end)
        if key in self.reached:
            return self.reached[key]
        found: dict[tuple[str, int], list[str]] = {}
        frontier: list[tuple[str, set[str], list[str]]] = []
        for fn, calls in self._seeds(rel, start, end):
            if fn is not None:
                found[(fn.file, fn.start)] = []
            frontier.append((rel, calls, []))
        for _depth in range(MAX_DEPTH):
            following: list[tuple[str, set[str], list[str]]] = []
            for file, calls, chain in frontier:
                for name in sorted(calls):
                    for fn in self._resolve(file, name):
                        if (fn.file, fn.start) not in found:
                            found[(fn.file, fn.start)] = [*chain, name]
                            following.append((fn.file, fn.calls, [*chain, name]))
            frontier = following
        self.reached[key] = found
        return found

    def chain_to(self, rel: str, start: int, end: int, path: str, line: int) -> list[str] | None:
        """The calls from a handler to the function holding path:line; None if it isn't reached."""
        if path not in self.family or self.family.get(rel) != self.family[path]:
            return None
        reached = self.reachable(rel, start, end)
        holders = [f for f in self.functions_at(path, line) if (f.file, f.start) in reached]
        if not holders:
            return None
        return reached[(holders[-1].file, holders[-1].start)]

    def link(self, routes: list[tuple[str, int, int]]) -> None:
        """Index every route's reach once, so each finding is a lookup, not a walk of all routes."""
        self._links = {}
        for i, (rel, start, end) in enumerate(routes):
            for where, chain in self.reachable(rel, start, end).items():
                self._links.setdefault(where, []).append((i, chain))

    def routes_reaching(self, path: str, line: int) -> dict[int, list[str]]:
        """{index in link()'s list: the calls leading to the function holding path:line}."""
        out: dict[int, list[str]] = {}
        if self._links is None or path not in self.family:
            return out
        for fn in self.functions_at(path, line):  # outermost first, so the innermost wins
            for i, chain in self._links.get((fn.file, fn.start), []):
                out[i] = chain
        return out

    def constant_input(self, path: str, line: int, rule: str) -> bool:
        """Whether a code finding's sink only ever sees values built from literals. A rule that
        traced the data from a request has already answered this."""
        if _TAINTED_RULE.search(rule) or path not in self.family:
            return False
        holders = self.functions_at(path, line)
        if not holders:
            return False
        try:
            text = (self.root / path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return False
        if line > len(text):
            return False
        sink = text[line - 1]
        call = sink[sink.find("(") + 1 : sink.rfind(")")] if "(" in sink else sink
        return built_from_constants(text[holders[-1].start : line - 1], call)

    def functions_at(self, path: str, line: int) -> list[Function]:
        info = self._load(path)
        if info is None:
            return []
        return sorted((f for f in info.functions if f.start <= line <= f.end), key=lambda f: f.start)
