"""Application-level assets for repositories without (much) infrastructure code.

Most application repositories carry no Terraform or Kubernetes, yet the database the code talks
to is the crown jewel. It is found from evidence in the code: database drivers and ORMs the code
imports, and connection settings such as DATABASE_URL. It is added only when no infrastructure
source already defines a database, so a real RDS instance is never shadowed by a guess.

An application with HTTP routes and no deployment configuration at all is modeled as one workload
that is assumed to be internet-facing (medium confidence, stated in the coverage line).
"""

from __future__ import annotations

import re

from breachgraph.graph.model import (
    CONTROL,
    INTERNET_ID,
    Confidence,
    Edge,
    EdgeKind,
    Evidence,
    Graph,
    Node,
    NodeKind,
    internet,
)
from breachgraph.graph.sources.common import SourceContext
from breachgraph.paths import iter_files
from breachgraph.reachability.imports import ImportIndex

APP_ID = "app:application"
DB_PREFIX = "app:database:"

# Imports that mean "this code queries a database": import name -> engine/library label.
DRIVERS: dict[str, str] = {
    # Python
    "sqlalchemy": "SQLAlchemy",
    "psycopg2": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "pymysql": "MySQL",
    "MySQLdb": "MySQL",
    "sqlite3": "SQLite",
    "pymongo": "MongoDB",
    "motor": "MongoDB",
    "peewee": "Peewee",
    "django": "Django ORM",
    # JavaScript / TypeScript
    "sequelize": "Sequelize",
    "pg": "PostgreSQL",
    "mysql": "MySQL",
    "mysql2": "MySQL",
    "mongoose": "MongoDB",
    "mongodb": "MongoDB",
    "typeorm": "TypeORM",
    "knex": "Knex",
    "@prisma/client": "Prisma",
    "better-sqlite3": "SQLite",
    "@supabase/supabase-js": "Supabase",
    "firebase-admin": "Firebase",
    # Go
    "database/sql": "SQL database",
    "gorm.io/gorm": "GORM",
    "github.com/jackc/pgx": "PostgreSQL",
    "go.mongodb.org/mongo-driver": "MongoDB",
    # Java
    "java.sql": "JDBC",
    "javax.persistence": "JPA",
    "jakarta.persistence": "JPA",
    "org.hibernate": "Hibernate",
}
# Connection settings in env files, compose files, manifests and config.
_SETTING = re.compile(
    r"\b(DATABASE_URL|DB_URL|SQLALCHEMY_DATABASE_URI|POSTGRES(?:QL)?_(?:URL|HOST|PASSWORD|DB)|"
    r"MYSQL_(?:URL|HOST|PASSWORD|DATABASE)|MONGO(?:DB)?_(?:URI|URL)|SUPABASE_SERVICE_ROLE_KEY|"
    r"FIREBASE_SERVICE_ACCOUNT)\b"
)
_SETTING_FILES = re.compile(
    r"(?:^|/)(?:\.env[^/]*|[^/]*\.ya?ml|[^/]*\.toml|[^/]*\.json|[^/]*\.ini|Dockerfile[^/]*|[^/]*\.properties)$"
)


def application_assets(ctx: SourceContext, graph: Graph, index: ImportIndex, route_count: int) -> None:
    has_db = any(n.kind is NodeKind.DATASTORE and n.attrs.get("queryable") for n in graph.nodes.values())
    if not has_db:
        _database(ctx, graph, index)
    # Workloads that run application code (CI jobs don't serve the application or hold its
    # database connection).
    apps = [w for w in graph.of_kind(NodeKind.WORKLOAD) if w.attrs.get("platform") != "github-actions"]
    if route_count and not apps:
        apps = [_implicit_application(graph)]
    # The application holds a connection to its database: whoever controls the application can use it.
    for db in [n for n in graph.nodes.values() if n.id.startswith(DB_PREFIX)]:
        for w in apps:
            graph.add_edge(
                Edge(
                    src=w.id,
                    dst=db.id,
                    kind=EdgeKind.CONNECTS_TO,
                    requires=CONTROL,
                    evidence=db.evidence[:1],
                    confidence=Confidence.MEDIUM,
                    note="the application's own database connection",
                )
            )


def _database(ctx: SourceContext, graph: Graph, index: ImportIndex) -> None:
    hits: dict[str, Evidence] = {}
    for path, fi in sorted(index.files.items()):
        for name in fi.externals:
            label = DRIVERS.get(name)
            if label and label not in hits:
                hits[label] = Evidence(path=path, detail=f"imports {name}", source="app")
    setting: Evidence | None = None
    for file, rel in iter_files(ctx.root, ctx.exclude):
        if not _SETTING_FILES.search(rel) or file.stat().st_size > 512_000:
            continue
        text = ctx.read(file)
        m = _SETTING.search(text or "")
        if m and text is not None:
            setting = Evidence(
                path=rel, line=text.count("\n", 0, m.start()) + 1, detail=m.group(1), source="app"
            )
            break
    if not hits and setting is None:
        return
    label = next(iter(hits), "database")
    described = ", ".join(list(hits)[:2]) or (setting.detail if setting else "database")
    evidence = [*hits.values(), *([setting] if setting else [])][:4]
    graph.add_node(
        Node(
            id=f"{DB_PREFIX}{label.lower().replace(' ', '-')}",
            kind=NodeKind.DATASTORE,
            name=f"Application database ({described})",
            value=8,
            attrs={"platform": "app", "queryable": True, "relational": True, "implicit": True},
            evidence=evidence,
        )
    )


def _implicit_application(graph: Graph) -> Node:
    graph.add_node(internet())
    node = graph.add_node(
        Node(
            id=APP_ID,
            kind=NodeKind.WORKLOAD,
            name="Application (no deployment configuration)",
            attrs={"platform": "app", "code_paths": [""], "implicit": True},
        )
    )
    graph.add_edge(
        Edge(
            src=INTERNET_ID,
            dst=APP_ID,
            kind=EdgeKind.EXPOSES,
            confidence=Confidence.MEDIUM,
            note="assumed internet-facing: the repository serves HTTP routes and has no deployment "
            "configuration that says otherwise",
        )
    )
    return node
