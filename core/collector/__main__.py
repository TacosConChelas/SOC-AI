"""Entry point: python -m core.collector"""

import os

from core.observability.metrics import start_http_server

if __name__ == "__main__":
    start_http_server(int(os.getenv("SOC_METRICS_PORT", "9109")))

    # Deps are constructed here at runtime (outside tests).
    # Instantiate Collector and call .poll_once() in a loop once
    # the full dep-injection wiring exists (docker-compose increment, C.4 of the plan).
    raise SystemExit("collector entrypoint: wire WazuhClient, RedisBus, pg_conn and call Collector.poll_once()")
