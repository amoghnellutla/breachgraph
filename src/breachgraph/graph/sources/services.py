"""Stock services that answer anyone: exposing one is a way in with no bug in your code.

A service only counts when its own defaults, in the version and settings shown, leave it open. A
setting we can't read, such as a mounted config file, means no claim: this list has to stay quiet on
a well-run deployment.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from breachgraph.graph.model import (
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    Weakness,
    WeaknessClass,
)


@dataclass(frozen=True)
class OpenService:
    name: str  # what it is
    why: str  # why it answers anyone
    holds: str  # what the attacker gets
    value: int


_REDIS = OpenService("Redis", "has no password", "Data in Redis", 8)
_MONGO = OpenService("MongoDB", "has no root user", "Data in MongoDB", 9)
_MEMCACHED = OpenService("Memcached", "has no authentication", "Data in Memcached", 7)
_ELASTIC = OpenService("Elasticsearch", "has security turned off", "Data in Elasticsearch", 9)
_GRAFANA = OpenService("Grafana", "keeps the default admin password", "Grafana and its data sources", 8)
_MINIO = OpenService("MinIO", "keeps the default root login", "Buckets in MinIO", 9)
_JUPYTER = OpenService("Jupyter", "has its token turned off", "A shell on the notebook server", 9)
_REGISTRY = OpenService("Docker registry", "has no authentication", "Images in this registry", 8)

_NAME = re.compile(r"(?:^|/)([a-z0-9._-]+?)(?::([^@]+))?(?:@sha256:[0-9a-f]+)?$")
_OLD_ELASTIC = re.compile(r"^[1-7]\.")
_CONFIG_FILE = re.compile(r"\.conf\b|\.ya?ml\b|--config\b")


def _has(env: Mapping[str, str], *names: str) -> bool:
    return any(n in env for n in names)


def open_service(image: str, env: Mapping[str, str], command: str = "") -> OpenService | None:
    """The service `image` runs, if these settings leave it open to anyone who reaches it."""
    m = _NAME.search(image.lower())
    if not m:
        return None
    name, tag = m.group(1), m.group(2) or ""
    if name in ("redis", "valkey", "keydb"):
        secured = _has(env, "REDIS_PASSWORD", "REDIS_ARGS") or "--requirepass" in command
        return None if secured or _CONFIG_FILE.search(command) else _REDIS
    if name == "mongo" or name == "mongodb":
        secured = _has(
            env, "MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD", "MONGODB_ROOT_PASSWORD"
        )
        return None if secured or _CONFIG_FILE.search(command) or "--auth" in command else _MONGO
    if name == "memcached":
        return None if "--enable-sasl" in command or " -S" in f" {command}" else _MEMCACHED
    if name == "elasticsearch":
        off = env.get("xpack.security.enabled", "").lower() == "false"
        unset = "xpack.security.enabled" not in env and bool(_OLD_ELASTIC.match(tag))
        return _ELASTIC if off or unset else None
    if name == "grafana" or name == "grafana-oss":
        secured = _has(env, "GF_SECURITY_ADMIN_PASSWORD", "GF_SECURITY_ADMIN_PASSWORD__FILE")
        return None if secured else _GRAFANA
    if name == "minio":
        secured = _has(env, "MINIO_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD_FILE", "MINIO_SECRET_KEY")
        return None if secured else _MINIO
    if name.endswith("-notebook") or name == "jupyterhub":
        return _JUPYTER if re.search(r"token=(?:''|\"\"|\s|$)", command) else None
    if name == "registry":
        return None if _has(env, "REGISTRY_AUTH", "REGISTRY_AUTH_HTPASSWD_PATH") else _REGISTRY
    return None


def mark_open(
    graph: Graph,
    node: Node,
    found: OpenService,
    evidence: Evidence,
    sure: Confidence = Confidence.HIGH,
) -> None:
    """The service's own defaults are the weakness, so reaching it needs nothing more."""
    node.weaknesses.append(
        Weakness(
            cls=WeaknessClass.AUTH_BYPASS,
            title=f"{found.name} {found.why}",
            evidence=evidence,
            confidence=sure,
        )
    )
    jewel = graph.add_node(
        Node(
            id=f"service:{node.id}",
            kind=NodeKind.DATASTORE,
            name=f"{found.holds} ({node.name})",
            value=found.value,
            evidence=[evidence],
        )
    )
    graph.add_edge(
        Edge(
            src=node.id,
            dst=jewel.id,
            kind=EdgeKind.CONNECTS_TO,
            requires=[WeaknessClass.AUTH_BYPASS],
            evidence=[evidence],
            note=f"{found.name} {found.why}",
        )
    )
