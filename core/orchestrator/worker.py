"""Worker — Redis Streams consumer loop that drives the TriageGraph."""

from __future__ import annotations

import threading
import time

from core.bus.streams import PendingEvent, RedisBus
from core.observability.metrics import EVENTS_PROCESSED, TRIAGE_DURATION
from core.orchestrator.graph import TriageGraph, TriageState


class Worker:
    def __init__(
        self,
        bus: RedisBus,
        graph: TriageGraph,
        consumer_name: str = "worker-0",
    ) -> None:
        self._bus = bus
        self._graph = graph
        self._consumer = consumer_name

    def run_once(self) -> bool:
        """Read and process one event. Returns True if an event was processed."""
        pending = self._bus.read_one(self._consumer)
        if pending is None:
            return False
        self._process(pending)
        return True

    def run(self, stop: threading.Event | None = None) -> None:
        """Blocking run loop. Claims stale messages first, then polls indefinitely.

        Exits when stop is set or KeyboardInterrupt is raised.
        """
        for stale in self._bus.claim_stale(self._consumer):
            self._process(stale)

        while stop is None or not stop.is_set():
            try:
                self.run_once()
            except KeyboardInterrupt:
                break

    def _process(self, pending: PendingEvent) -> None:
        start = time.monotonic()
        state: TriageState = self._graph.run(pending.event)
        elapsed = time.monotonic() - start

        TRIAGE_DURATION.observe(elapsed)
        outcome = "dead_letter" if state["dead_letter"] is not None else "success"
        EVENTS_PROCESSED.labels(outcome=outcome).inc()

        self._bus.ack(pending.msg_id)
