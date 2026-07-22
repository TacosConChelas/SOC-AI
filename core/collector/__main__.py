"""Collector entrypoint — wires Collector from env and runs the poll loop."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

import psycopg
import redis

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.collector.collector import Collector, WazuhClient
from core.observability.metrics import start_http_server

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
    wazuh_url = _require("WAZUH_API_URL")
    wazuh_user = _require("WAZUH_API_USER")
    wazuh_pass = _require("WAZUH_API_PASSWORD")

    redis_user = os.getenv("REDIS_USER")
    redis_password = os.getenv("REDIS_PASSWORD")
    metrics_port = int(os.getenv("METRICS_PORT", "9109"))
    poll_interval_s = float(os.getenv("POLL_INTERVAL_S", "10"))

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

    pg_conn = psycopg.connect(pg_dsn)
    collector = Collector(
        WazuhClient(base_url=wazuh_url, user=wazuh_user, password=wazuh_pass),
        bus,
        pg_conn,
    )

    start_http_server(metrics_port)
    log.info("collector started — metrics on :%d, poll interval %.1fs", metrics_port, poll_interval_s)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    try:
        while not stop.is_set():
            try:
                published = collector.poll_once()
                if published:
                    log.info("published %d events", published)
            except Exception as exc:
                log.error("poll_once error: %s", exc)
            stop.wait(poll_interval_s)
    finally:
        pg_conn.close()
        log.info("collector stopped")


if __name__ == "__main__":
    main()
