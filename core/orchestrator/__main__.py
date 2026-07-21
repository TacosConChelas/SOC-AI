"""Entry point: python -m core.orchestrator"""

import os

from core.observability.metrics import start_http_server

if __name__ == "__main__":
    start_http_server(int(os.getenv("SOC_METRICS_PORT", "9108")))

    # Deps are constructed here at runtime (outside tests).
    # Instantiate Worker and call .run() once the full dep-injection
    # wiring exists (docker-compose increment, C.4 of the plan).
    raise SystemExit("worker entrypoint: wire TriageDeps and call Worker(bus, graph).run()")
