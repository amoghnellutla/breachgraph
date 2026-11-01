"""HTTP route discovery with tree-sitter: which code is reachable from a request, and where.

Supported: Python (Flask, FastAPI, Starlette-style decorators, Django urls.py, class-based views
and Django REST Framework), JavaScript / TypeScript (Express/Koa/Fastify/Hono-style routers, NestJS
decorators, Next.js route files, tRPC procedures), Java (Spring MVC and JAX-RS annotations), Go
(net/http, Gin, Echo, Chi, gorilla/mux).

Each route records the handler's line range so scanner findings inside it can be attached.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tree_sitter as ts
import tree_sitter_go as ts_go
import tree_sitter_java as ts_java
import tree_sitter_javascript as ts_js
import tree_sitter_python as ts_py
import tree_sitter_typescript as ts_ts

from breachgraph.graph.sources.auth import annotate
from breachgraph.graph.sources.common import SourceContext

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "all",
    "any",
    "route",
    "api_route",
    "websocket",
}
_LANGS: dict[str, Any] = {
    ".py": ts_py.language(),
    ".js": ts_js.language(),
    ".mjs": ts_js.language(),
    ".cjs": ts_js.language(),
    ".jsx": ts_js.language(),
    ".ts": ts_ts.language_typescript(),
    ".tsx": ts_ts.language_tsx(),
    ".java": ts_java.language(),
    ".go": ts_go.language(),
}
_PARSERS: dict[str, ts.Parser] = {}


@dataclass
class Route:
    method: str
    path: str
    file: str
    start_line: int
    end_line: int
    handler: str
    framework: str
    auth: str = ""  # the guard in front of it, when its declaration shows one (see sources/auth.py)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.handler.isidentifier():
            self.handler = "<inline>"

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


def _parser(suffix: str) -> ts.Parser:
    if suffix not in _PARSERS:
        _PARSERS[suffix] = ts.Parser(ts.Language(_LANGS[suffix]))
    return _PARSERS[suffix]


def _text(node: ts.Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _string(node: ts.Node | None) -> str | None:
    """Value of a string literal node (any language), else None."""
    if node is None:
        return None
    if node.type in (
        "string",
        "string_literal",
        "interpreted_string_literal",
        "raw_string_literal",
        "template_string",
    ):
        raw = _text(node)
        m = re.match(r'^[rbuRBUf]*(["\'`]{1,3})(.*)\1$', raw, re.S)
        return m.group(2) if m else raw.strip("\"'`")
    return None


def _walk(node: ts.Node) -> Iterator[ts.Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _lines(node: ts.Node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


class RouteSource:
    name = "routes"

    def __init__(self) -> None:
        self.routes: list[Route] = []

    def collect(self, ctx: SourceContext) -> list[Route]:
        for path in ctx.files(*_LANGS):
            try:
                found = routes_in_file(path, ctx.rel(path))
            except ValueError:
                ctx.skipped.append(f"{ctx.rel(path)}: could not parse")
                continue
            if found:
                annotate(found, ctx.read(path) or "")
            self.routes += found
        return self.routes


def parse_tree(path: Path) -> ts.Tree | None:
    """Parse a supported source file. None for other languages or binary files; raises
    ValueError if the grammar fails."""
    suffix = path.suffix.lower()
    if suffix not in _LANGS:
        return None
    data = path.read_bytes()
    if b"\0" in data[:1024]:
        return None
    try:
        return _parser(suffix).parse(data)
    except Exception as exc:  # grammar errors are recoverable by design; this is a safety net
        raise ValueError(str(exc)) from exc


# A file with none of these declares no route, so it needn't be parsed. Walking every syntax tree
# in a large frontend (translations, generated data) took minutes and found nothing.
_MAY_ROUTE = re.compile(
    rb"\.(?:get|post|put|patch|delete|all|any|head|options|route|handle|handlefunc|api_route|websocket)\s*[(<]"
    rb"|@(?:Get|Post|Put|Patch|Delete|All|Controller)\b|rocedure\b|\bre_path\(|\bpath\(|\burl\(",
    re.I,
)


def routes_in_file(path: Path, rel: str) -> list[Route]:
    """Routes declared in one source file. Raises ValueError if the file can't be parsed."""
    if path.suffix.lower() in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx") and not _NEXT_ROUTE.search(rel):
        try:
            if not _MAY_ROUTE.search(path.read_bytes()):
                return []
        except OSError:
            return []
    tree = parse_tree(path)
    if tree is None:
        return []
    suffix = path.suffix.lower()
    root = tree.root_node
    if suffix == ".py":
        return _python(root, rel)
    if suffix == ".java":
        return _java(root, rel)
    if suffix == ".go":
        return _go(root, rel)
    return _javascript(root, rel, path)


# ------------------------------------------------------------------ Python


# Class-based views: each HTTP-named method, and DRF's @action methods, is a route.
_VIEW_BASE = re.compile(r"ViewSet\b|APIView\b|\bMethodView\b|\b(?:views\.)?View\b|Mixin.*ViewSet")
_VIEW_METHODS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "list": "GET",
    "retrieve": "GET",
    "create": "POST",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
}


def _class_views(root: ts.Node, rel: str) -> list[Route]:
    out: list[Route] = []
    for cls in (n for n in _walk(root) if n.type == "class_definition"):
        if not _VIEW_BASE.search(_text(cls.child_by_field_name("superclasses"))):
            continue
        name = _text(cls.child_by_field_name("name"))
        body = cls.child_by_field_name("body")
        for item in body.children if body else []:
            fn = item.child_by_field_name("definition") if item.type == "decorated_definition" else item
            if fn is None or fn.type != "function_definition":
                continue
            method = _text(fn.child_by_field_name("name"))
            action = item.type == "decorated_definition" and "action(" in _text(item).split("def ")[0]
            if method in _VIEW_METHODS or action:
                start, end = _lines(item)
                verb = _VIEW_METHODS.get(method, "ANY")
                out.append(Route(verb, f"/{name}/{method}", rel, start, end, method, "drf"))
    return out


def _python(root: ts.Node, rel: str) -> list[Route]:
    out: list[Route] = _class_views(root, rel)
    funcs = {_text(n.child_by_field_name("name")): n for n in _walk(root) if n.type == "function_definition"}
    for n in _walk(root):
        if n.type == "call" and _text(n.child_by_field_name("function")).endswith(".add_url_rule"):
            args = n.child_by_field_name("arguments")
            first = next((a for a in (args.children if args else []) if a.type == "string"), None)
            if (rule := _string(first)) is not None:
                start, end = _lines(n)
                out.append(Route("ANY", rule, rel, start, end, "<inline>", "flask"))
        if n.type == "decorated_definition":
            fn = n.child_by_field_name("definition")
            if fn is None or fn.type != "function_definition":
                continue
            for dec in (c for c in n.children if c.type == "decorator"):
                call = next((c for c in dec.children if c.type == "call"), None)
                if call is None:
                    continue
                func = call.child_by_field_name("function")
                attr = _text(func).rsplit(".", 1)[-1].lower() if func else ""
                if attr not in HTTP_METHODS:
                    continue
                args = call.child_by_field_name("arguments")
                first = next((a for a in (args.children if args else []) if a.type == "string"), None)
                path = _string(first)
                if path is None:
                    continue
                method = attr
                if attr in ("route", "api_route"):
                    m = re.search(r"methods\s*=\s*\[([^\]]*)\]", _text(args))
                    method = m.group(1).replace('"', "").replace("'", "").replace(" ", "") if m else "GET"
                start, end = _lines(n)
                framework = "fastapi" if attr in ("api_route",) or "router" in _text(func) else "flask"
                out.append(
                    Route(
                        method,
                        path,
                        rel,
                        start,
                        end,
                        _text(fn.child_by_field_name("name")),
                        framework,
                    )
                )
        # Django: path("x/", views.handler) / re_path(...)
        elif n.type == "call" and _text(n.child_by_field_name("function")) in (
            "path",
            "re_path",
            "url",
        ):
            args = n.child_by_field_name("arguments")
            items = [a for a in (args.children if args else []) if a.type not in ("(", ")", ",")]
            if len(items) >= 2 and (route := _string(items[0])) is not None:
                handler = _text(items[1]).rsplit(".", 1)[-1]
                start, end = _lines(n)
                if handler in funcs:  # view defined in the same file
                    start, end = _lines(funcs[handler])
                out.append(Route("ANY", "/" + route.lstrip("^/"), rel, start, end, handler, "django"))
    return out


# ------------------------------------------------------------------ JavaScript / TypeScript

_NEXT_ROUTE = re.compile(r"(?:^|/)(?:pages/api/(.+?)|app/(.*?)/?route)\.(?:js|jsx|ts|tsx|mjs)$")


def _trpc(pair: ts.Node, rel: str) -> list[Route]:
    """`getUser: protectedProcedure.input(...).query(async ...)` inside a router."""
    value = pair.child_by_field_name("value")
    if value is None or value.type != "call_expression":
        return []
    func = value.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return []
    verb = _text(func.child_by_field_name("property"))
    if verb not in ("query", "mutation") or not re.search(
        r"procedure\b", _text(func.child_by_field_name("object")), re.I
    ):
        return []
    start, end = _lines(pair)
    name = _text(pair.child_by_field_name("key")).strip("'\"")
    return [Route("POST", f"/trpc/{name}", rel, start, end, name, "trpc")]


def _javascript(root: ts.Node, rel: str, path: Path) -> list[Route]:
    out: list[Route] = []
    m = _NEXT_ROUTE.search(rel)
    if m:
        next_url = "/" + (("api/" + m.group(1)) if m.group(1) else (m.group(2) or ""))
        next_url = re.sub(r"/index$", "", re.sub(r"\[(\.\.\.)?(\w+)\]", r":\2", next_url)) or "/"
        start, end = _lines(root)
        out.append(Route("ANY", next_url, rel, start, end, path.stem, "nextjs"))
    controller_prefix = ""
    for n in _walk(root):
        if n.type == "pair":  # one walk, not one per kind of route
            out += _trpc(n, rel)
        elif n.type == "call_expression":
            func = n.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue
            method = _text(func.child_by_field_name("property")).lower()
            if method not in HTTP_METHODS:
                continue
            args = n.child_by_field_name("arguments")
            items = [a for a in (args.children if args else []) if a.type not in ("(", ")", ",")]
            if len(items) < 2 or (url := _string(items[0])) is None or not url.startswith("/"):
                continue
            start, end = _lines(n)
            out.append(
                Route(
                    method,
                    url,
                    rel,
                    start,
                    end,
                    _text(items[-1])[:60] if items[-1].type == "identifier" else "<inline>",
                    "express",
                )
            )
        elif n.type == "decorator":  # NestJS
            text = _text(n)
            cm = re.match(r"@Controller\(\s*['\"`]([^'\"`]*)", text)
            if cm:
                controller_prefix = "/" + cm.group(1).strip("/")
                continue
            dm = re.match(r"@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['\"`]([^'\"`]*))?", text)
            if dm and n.parent is not None:
                method_node = n.parent if n.parent.type == "method_definition" else n.next_named_sibling
                if method_node is None:
                    continue
                start, end = _lines(method_node)
                url = (controller_prefix.rstrip("/") + "/" + (dm.group(2) or "").strip("/")) or "/"
                out.append(
                    Route(
                        dm.group(1),
                        url,
                        rel,
                        start,
                        end,
                        _text(method_node.child_by_field_name("name")),
                        "nestjs",
                    )
                )
    return out


# ------------------------------------------------------------------ Java (Spring)

_SPRING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b(?:\((.*)\))?", re.S)
_JAXRS_VERB = re.compile(r"@(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)")
_JAXRS_PATH = re.compile(r"@Path\(\s*\"([^\"]*)\"")


def _spring_path(args: str | None) -> str:
    if not args:
        return ""
    m = re.search(r'(?:value|path)\s*=\s*\{?\s*"([^"]*)"', args) or re.search(r'"([^"]*)"', args)
    return m.group(1) if m else ""


def _jaxrs(cls: ts.Node, rel: str, prefix: str) -> list[Route]:
    """JAX-RS: `@GET` on a method, with `@Path` on the class and optionally the method."""
    out: list[Route] = []
    body = cls.child_by_field_name("body")
    for meth in (c for c in (body.children if body else []) if c.type == "method_declaration"):
        mmods = next((c for c in meth.children if c.type == "modifiers"), None)
        notes = [_text(a) for a in (mmods.children if mmods else [])]
        verb = next((n[1:] for n in notes if _JAXRS_VERB.fullmatch(n)), None)
        if verb is None:
            continue
        sub = next((m.group(1) for n in notes if (m := _JAXRS_PATH.match(n))), "")
        url = "/" + "/".join(p.strip("/") for p in (prefix, sub) if p.strip("/"))
        start, end = _lines(meth)
        out.append(Route(verb, url, rel, start, end, _text(meth.child_by_field_name("name")), "jaxrs"))
    return out


def _java(root: ts.Node, rel: str) -> list[Route]:
    out: list[Route] = []
    for cls in (n for n in _walk(root) if n.type == "class_declaration"):
        prefix = ""
        mods = next((c for c in cls.children if c.type == "modifiers"), None)
        jaxrs = ""
        for ann in mods.children if mods else []:
            if jp := _JAXRS_PATH.match(_text(ann)):
                jaxrs = jp.group(1)
            m = _SPRING.match(_text(ann))
            if m and m.group(1) == "Request":
                prefix = _spring_path(m.group(2))
        if jaxrs:
            out += _jaxrs(cls, rel, jaxrs)
        body = cls.child_by_field_name("body")
        for meth in (c for c in (body.children if body else []) if c.type == "method_declaration"):
            mmods = next((c for c in meth.children if c.type == "modifiers"), None)
            for ann in mmods.children if mmods else []:
                m = _SPRING.match(_text(ann))
                if not m:
                    continue
                verb = m.group(1)
                if verb == "Request":
                    vm = re.search(r"RequestMethod\.(\w+)", m.group(2) or "")
                    verb = vm.group(1) if vm else "ANY"
                url = "/" + "/".join(p.strip("/") for p in (prefix, _spring_path(m.group(2))) if p.strip("/"))
                start, end = _lines(meth)
                out.append(
                    Route(
                        verb,
                        url,
                        rel,
                        start,
                        end,
                        _text(meth.child_by_field_name("name")),
                        "spring",
                    )
                )
    return out


# ------------------------------------------------------------------ Go

_GO_METHODS = {
    "handlefunc",
    "handle",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "any",
    "head",
    "options",
}


def _go(root: ts.Node, rel: str) -> list[Route]:
    out: list[Route] = []
    funcs = {
        _text(n.child_by_field_name("name")): n
        for n in _walk(root)
        if n.type in ("function_declaration", "method_declaration")
    }
    for n in _walk(root):
        if n.type != "call_expression":
            continue
        func = n.child_by_field_name("function")
        if func is None or func.type != "selector_expression":
            continue
        method = _text(func.child_by_field_name("field"))
        if method.lower() not in _GO_METHODS:
            continue
        args = n.child_by_field_name("arguments")
        items = [a for a in (args.children if args else []) if a.type not in ("(", ")", ",")]
        if len(items) < 2 or (url := _string(items[0])) is None or not url.startswith("/"):
            continue
        handler = _text(items[-1])
        start, end = _lines(n)
        if handler in funcs:
            start, end = _lines(funcs[handler])
        verb = "ANY" if method.lower() in ("handlefunc", "handle", "any") else method.upper()
        out.append(Route(verb, url, rel, start, end, handler[:60], "go"))
    return out
