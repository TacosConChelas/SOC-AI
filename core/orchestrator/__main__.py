"""Orchestrator entrypoint — wires TriageDeps from env and runs the Worker loop."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

import psycopg
import redis
from opensearchpy import OpenSearch

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.notify.clients import MultiNotifier
from core.notify.system_notifier import SystemNotifier
from core.observability.metrics import start_http_server
from core.orchestrator.graph import TriageDeps, TriageGraph
from core.orchestrator.nodes.classify import OllamaClient
from core.orchestrator.nodes.group import SessionStore
from core.orchestrator.worker import Worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger(__name__)


def _require(name: str) -> str:
    val = os.getenv(name)
    if not val:
        print(f"FATAL: required env var {name!r} is not set", file=sys.stderr)
        sys.exit(1)
    return val


def main() -> None:
    pg_dsn = _require("POSTGRES_DSN")
    os_url = _require("OPENSEARCH_URL")

    redis_user = os.getenv("REDIS_USER")
    redis_password = os.getenv("REDIS_PASSWORD")
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "soc-ai-triage")
    os_user = os.getenv("OPENSEARCH_USER")
    os_password = os.getenv("OPENSEARCH_PASSWORD")
    metrics_port = int(os.getenv("METRICS_PORT", "9108"))

    config = BusConfig()
    redis_client: redis.Redis = redis.Redis.from_url(
        config.redis_url,
        username=redis_user,
        password=redis_password,
        decode_responses=True,
        socket_timeout=config.socket_timeout_s,
    )
    bus = RedisBus(redis_client, config)
    bus.ensure_group()

    os_client = OpenSearch(
        hosts=[os_url],
        use_ssl=os_url.startswith("https"),
        http_auth=(os_user, os_password) if (os_user and os_password) else None,
    )

    pg_conn = psycopg.connect(pg_dsn)

    deps = TriageDeps(
        os_client=os_client,
        ollama_client=OllamaClient(base_url=ollama_url, model=ollama_model),
        session_store=SessionStore(redis_client),
        pg_conn=pg_conn,
        dead_letter_bus=bus,
        notifier=MultiNotifier.from_env(),
        system_notifier=SystemNotifier.from_env(),
    )
    worker = Worker(bus, TriageGraph(deps))

    start_http_server(metrics_port)
    log.info("orchestrator started — metrics on :%d", metrics_port)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    try:
        worker.run(stop=stop)
    finally:
        pg_conn.close()
        log.info("orchestrator stopped")


if __name__ == "__main__":
    main()
