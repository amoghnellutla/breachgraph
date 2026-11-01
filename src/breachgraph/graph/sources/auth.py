"""Which routes sit behind a login, read from how they are declared.

This is a label, not a proof. A path through a guarded route is still reported, because many
applications let anyone create an account; it says "needs a login" and ranks below anonymous
paths. Only guards visible in the declaration count: the route's own middleware, decorators and
annotations, a guard on its class, and `use(guard)` or a guarded group in the same file. A guard
mounted from another file, or a global security filter, is not seen, so the route stays anonymous
and the report errs towards the attacker.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from breachgraph.graph.sources.routes import Route

_GUARD = re.compile(
    r"\b(?:login_required|jwt_required|auth_required|token_required|permission_required|"
    r"staff_member_required|user_passes_test|requires?_?(?:auth|login|user|admin|role|permission|session)\w*|"
    r"is_?(?:authenticated|authorized|logged_?in|admin)\w*|ensure_?(?:auth|logged)\w*|"
    r"authenticate\w*|authori[sz]e\w*|auth_?(?:middleware|guard|required)\w*|"
    r"get_current_\w*user\w*|current_active_user|verify_\w*token\w*|"
    r"PreAuthorize|Secured|RolesAllowed|UseGuards|AuthGuard|withAuth|JwtAuthGuard|"
    r"AuthRequired|AuthMiddleware|JWTAuth\w*|RequireAuth\w*|BasicAuth|"
    r"\w*(?:protected|authed|authenticated|private|admin)Procedure|RequiresAuthentication|RequiresUser)\b",
    re.I,
)
_BARE_AUTH = re.compile(r"[,(]\s*(auth)(?:\(\))?\s*[,)]")
_OPEN = re.compile(r"permitAll|AllowAnonymous|@Public\b|login_not_required", re.I)
_STRING = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`")
# Where a declaration ends and the handler's body begins.
_BODY = re.compile(r"=>|\{\s*$|:\s*$", re.M)
_USE = re.compile(r"\b(\w+)\.[Uu]se\(\s*(?:['\"`]([^'\"`]*)['\"`]\s*,)?(.*)\)\s*;?\s*$", re.M)
_GROUP = re.compile(r"\b(\w+)\s*:?=\s*\w+\.Group\(\s*['\"`]([^'\"`]*)['\"`]\s*,(.*)\)", re.M)
_CLASS = re.compile(r"^\s*(?:export\s+|public\s+|abstract\s+|final\s+)*class\s+\w+", re.M)
_RECEIVER = re.compile(r"^\s*(\w+)\s*\.")
_PERMISSIONS = re.compile(r"permission_classes\s*=.*\b(Is\w*(?:Authenticated|Admin)\w*)")


def _named(code: str) -> str:
    """The guard a piece of code applies, ignoring string contents such as `/auth/login`."""
    if _OPEN.search(code):
        return ""
    bare = _STRING.sub('""', code)
    if m := _GUARD.search(bare):
        return m.group(0)
    return "auth" if _BARE_AUTH.search(bare) else ""


def _declaration(lines: list[str], route: Route) -> str:
    """The route's decorators, signature and middleware, without its body."""
    first = route.start_line - 1
    while first > 0 and lines[first - 1].lstrip().startswith("@"):
        first -= 1
    text = "\n".join(lines[first : route.end_line])
    if route.framework in ("express", "go", "nextjs", "trpc"):
        return text[: m.start()] if (m := _BODY.search(text)) else text
    # Decorators and annotations come first; stop at the end of the signature.
    return text[: m.end()] if (m := re.search(r"\)\s*(?:->[^:\n]+)?:\s*$|\{\s*$", text, re.M)) else text


def _file_guards(text: str) -> list[tuple[str, str, int, str]]:
    """(receiver, path prefix, line, guard) for `app.use(guard)` and guarded groups."""
    out = []
    for rx in (_USE, _GROUP):
        for m in rx.finditer(text):
            if name := _named(m.group(3)):
                # A group's receiver is already scoped, and its routes omit the group's prefix.
                prefix = "" if rx is _GROUP else m.group(2) or ""
                out.append((m.group(1), prefix, text.count("\n", 0, m.start()) + 1, name))
    return out


def _drf_guard(lines: list[str], start: int) -> str:
    """`permission_classes = [IsAuthenticated]` in the class a method belongs to."""
    for line in reversed(lines[: start - 1]):
        if m := _PERMISSIONS.search(line):
            return m.group(1)
        if line.startswith("class "):
            return ""
    return ""


def annotate(routes: list[Route], text: str) -> None:
    """Set each route's ``auth`` to the guard in front of it, from its file's source."""
    if not routes:
        return
    lines = text.splitlines()
    guards = _file_guards(text)
    cls = _CLASS.search(text)
    class_guard = ""
    if cls:  # the annotations stacked on the class
        above = text[: cls.start()].splitlines()[-6:]
        class_guard = _named("\n".join(ln for ln in above if ln.lstrip().startswith("@")))
    for r in routes:
        if not 0 < r.start_line <= len(lines):
            continue
        receiver = _RECEIVER.match(lines[r.start_line - 1])
        r.auth = _named(_declaration(lines, r)) or class_guard
        if not r.auth and r.framework == "drf":
            r.auth = _drf_guard(lines, r.start_line)
        for var, prefix, line, name in guards:
            if r.auth:
                break
            # `/api/users/:id` guards `/api/users/7`; the parameter is the end of the prefix.
            scope = prefix.split(":")[0].rstrip("/")
            if receiver and receiver.group(1) == var and line < r.start_line and r.path.startswith(scope):
                r.auth = name
