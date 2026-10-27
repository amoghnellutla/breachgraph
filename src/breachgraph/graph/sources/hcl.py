"""Normalization of python-hcl2 (v8) output into plain Python values."""

from __future__ import annotations

import json
import re
from typing import Any

_REF_RE = re.compile(
    r"\b((?:data\.)?(?:aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z0-9_-]+)(?:\[[^\]]*\])?(?:\.([a-z_]+))?"
)


def unquote(value: Any) -> Any:
    """Strip hcl2's literal quotes and block markers recursively."""
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == value[-1] == '"':
            return value[1:-1]
        return value
    if isinstance(value, list):
        return [unquote(v) for v in value]
    if isinstance(value, dict):
        return {unquote(k): unquote(v) for k, v in value.items() if k != "__is_block__"}
    return value


def blocks(doc: dict[str, Any], section: str) -> list[tuple[str, str, dict[str, Any]]]:
    """[(type, name, body)] for every `resource`/`data` block in a parsed file."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    for entry in doc.get(section) or []:
        for rtype, named in unquote(entry).items():
            for name, body in named.items():
                out.append((rtype, name, body if isinstance(body, dict) else {}))
    return out


def refs(value: Any) -> list[str]:
    """Terraform references ("aws_iam_role.web", "data.aws_iam_policy_document.x") in a value."""
    text = json.dumps(value) if not isinstance(value, str) else value
    return sorted({m.group(1) for m in _REF_RE.finditer(text)})


def literal(value: Any) -> str | None:
    """A plain string value, or None when it's an expression we cannot evaluate."""
    if isinstance(value, str) and "${" not in value:
        return value
    return None


def truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def decode_policy(value: Any) -> dict[str, Any] | None:
    """Decode an IAM policy given as JSON text, heredoc, or `jsonencode({...})` expression."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("${jsonencode(") and text.endswith(")}"):
        text = _hcl_object_to_json(text[len("${jsonencode(") : -2])
    elif text.startswith("<<"):
        text = text.split("\n", 1)[1].rsplit("\n", 1)[0]
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _hcl_object_to_json(expr: str) -> str:
    """Best-effort conversion of an HCL object literal to JSON.

    Handles `key = value`, nested objects/lists, and bare references (quoted as "${ref}")."""
    out: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c == '"':  # copy string literal verbatim (may contain ${...})
            j = i + 1
            depth = 0
            while j < n:
                if expr[j] == "\\":
                    j += 2
                    continue
                if expr.startswith("${", j):
                    depth += 1
                elif expr[j] == "}" and depth:
                    depth -= 1
                elif expr[j] == '"' and depth == 0:
                    break
                j += 1
            out.append(expr[i : j + 1])
            i = j + 1
            k = i
            while k < n and expr[k] == " ":
                k += 1
            if k < n and expr[k] == "=" and not expr.startswith("==", k):
                out.append(":")  # a quoted key: "token.actions.githubusercontent.com:sub" = "..."
                i = k + 1
        elif c.isalpha() or c == "_":
            j, depth = i, 0
            # A reference may carry an index (`x[0]`), but a `]` it didn't open ends a list.
            while j < n and (
                expr[j].isalnum() or expr[j] in "_.-*" or expr[j] == "[" or (expr[j] == "]" and depth)
            ):
                depth += {"[": 1, "]": -1}.get(expr[j], 0)
                j += 1
            word = expr[i:j]
            k = j
            while k < n and expr[k] == " ":
                k += 1
            if k < n and expr[k] in "=:" and not expr.startswith("==", k):
                out.append(json.dumps(word) + ":")
                i = k + 1
            elif word in ("true", "false", "null"):
                out.append(word)
                i = j
            elif k < n and expr[k] == "(":
                # A function call (concat, merge, ...): its value is only known at apply time.
                depth, m = 0, k
                while m < n:
                    depth += {"(": 1, ")": -1}.get(expr[m], 0)
                    m += 1
                    if depth == 0:
                        break
                out.append(json.dumps("${" + expr[i:m] + "}"))
                i = m
            else:
                out.append(json.dumps("${" + word + "}"))
                i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)
