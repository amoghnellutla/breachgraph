"""An open service is a way in only when its own defaults say so, and silence beats a guess."""

from pathlib import Path

import pytest
import yaml

from breachgraph.graph.model import INTERNET_ID, Confidence, Graph
from breachgraph.graph.paths import find_paths
from breachgraph.graph.sources.common import SourceContext
from breachgraph.graph.sources.images import ImageSource
from breachgraph.graph.sources.kubernetes import KubernetesSource
from breachgraph.graph.sources.services import open_service


@pytest.mark.parametrize(
    ("image", "env", "command", "name"),
    [
        ("redis:7", {}, "", "Redis"),
        ("docker.io/library/redis:7-alpine", {}, "", "Redis"),
        ("redis:7", {"REDIS_PASSWORD": "x"}, "", None),
        ("redis:7", {}, "redis-server --requirepass x", None),
        ("redis:7", {}, "redis-server /etc/redis/redis.conf", None),  # can't read the file: no claim
        ("mongo:7", {}, "", "MongoDB"),
        ("mongo:7", {"MONGO_INITDB_ROOT_USERNAME": "u"}, "", None),
        ("elasticsearch:7.17.0", {}, "", "Elasticsearch"),
        ("elasticsearch:8.13.0", {}, "", None),  # secure by default since 8
        ("elasticsearch:8.13.0", {"xpack.security.enabled": "false"}, "", "Elasticsearch"),
        ("elasticsearch:7.17.0", {"xpack.security.enabled": "true"}, "", None),
        ("grafana/grafana:11.0.0", {}, "", "Grafana"),
        ("grafana/grafana:11.0.0", {"GF_SECURITY_ADMIN_PASSWORD": "x"}, "", None),
        ("minio/minio:latest", {}, "server /data", "MinIO"),
        ("minio/minio:latest", {"MINIO_ROOT_PASSWORD": "x"}, "server /data", None),
        ("jupyter/base-notebook:latest", {}, "", None),  # a token by default
        ("jupyter/base-notebook:latest", {}, "start-notebook.sh --NotebookApp.token=''", "Jupyter"),
        ("memcached:1.6", {}, "", "Memcached"),
        ("registry:2", {}, "", "Docker registry"),
        ("registry:2", {"REGISTRY_AUTH": "htpasswd"}, "", None),
        ("postgres:16", {}, "", None),  # refuses to start without a password
        ("nginx:1.27", {}, "", None),
        ("acme/redis-exporter:1", {}, "", None),
    ],
)
def test_the_verdict_for_each_service(
    image: str, env: dict[str, str], command: str, name: str | None
) -> None:
    found = open_service(image, env, command)
    assert (found.name if found else None) == name


def compose(tmp: Path, service: dict) -> Graph:  # type: ignore[type-arg]
    (tmp / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"cache": service}}), encoding="utf-8"
    )
    g = Graph()
    ImageSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def test_a_published_open_service_in_compose_is_a_lead(tmp_path: Path) -> None:
    paths = find_paths(compose(tmp_path, {"image": "redis:7", "ports": ["6379:6379"]}))
    assert [p.confidence for p in paths] == [Confidence.LOW]
    assert paths[0].target.name == "Data in Redis (compose service cache)"


def test_a_port_on_localhost_or_none_at_all_is_not_exposed(tmp_path: Path) -> None:
    assert not compose(tmp_path, {"image": "redis:7", "ports": ["127.0.0.1:6379:6379"]}).nodes
    assert not compose(tmp_path, {"image": "redis:7"}).nodes


def test_settings_given_as_a_list_count(tmp_path: Path) -> None:
    service = {"image": "mongo:7", "ports": ["27017:27017"], "environment": ["MONGO_INITDB_ROOT_PASSWORD=x"]}
    assert not compose(tmp_path, service).nodes


def cluster(tmp: Path, service_type: str) -> Graph:
    labels = {"app": "cache"}
    docs = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "cache", "namespace": "default"},
            "spec": {
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {"containers": [{"name": "c", "image": "redis:7"}]},
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "cache", "namespace": "default"},
            "spec": {"type": service_type, "selector": labels, "ports": [{"port": 6379}]},
        },
    ]
    (tmp / "all.yaml").write_text(yaml.safe_dump_all(docs), encoding="utf-8")
    g = Graph()
    KubernetesSource().collect(SourceContext(root=tmp, exclude=[]), g)
    return g


def test_an_open_service_behind_a_load_balancer_blocks(tmp_path: Path) -> None:
    paths = find_paths(cluster(tmp_path, "LoadBalancer"))
    assert [p.confidence for p in paths] == [Confidence.HIGH]
    assert paths[0].weaknesses == []  # derived from the manifest, not from a scanner


def test_an_open_service_inside_the_cluster_is_not_an_internet_path(tmp_path: Path) -> None:
    g = cluster(tmp_path, "ClusterIP")
    assert INTERNET_ID not in g.nodes or not find_paths(g)
