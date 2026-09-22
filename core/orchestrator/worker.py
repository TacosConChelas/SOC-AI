"""Worker — Redis Streams consumer loop that drives the TriageGraph."""

from __future__ import annotations

import logging
import threading
import time

from core.bus.streams import BusError, PendingEvent, RedisBus
from core.observability.metrics import EVENTS_PROCESSED, TRIAGE_DURATION
from core.orchestrator.graph import TriageGraph, TriageState
from core.orchestrator.nodes.classify import OllamaUnavailableError

log = logging.getLogger(__name__)

_OLLAMA_BACKOFF_INITIAL_S = 1.0
_OLLAMA_BACKOFF_MAX_S = 30.0
_BUS_BACKOFF_INITIAL_S = 1.0
_BUS_BACKOFF_MAX_S = 30.0


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
        self._ollama_backoff_s = _OLLAMA_BACKOFF_INITIAL_S
        self._bus_backoff_s = _BUS_BACKOFF_INITIAL_S

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
            except BusError as exc:
                log.warning("Redis unavailable — backing off %.1fs (%s)", self._bus_backoff_s, exc)
                time.sleep(self._bus_backoff_s)
                self._bus_backoff_s = min(self._bus_backoff_s * 2, _BUS_BACKOFF_MAX_S)
            else:
                self._bus_backoff_s = _BUS_BACKOFF_INITIAL_S

    def _process(self, pending: PendingEvent) -> None:
        start = time.monotonic()
        try:
            state: TriageState = self._graph.run(pending.event)
        except OllamaUnavailableError:
            # ADR-0004 §2 fail-loud posture: leave the message unacked in the
            # PEL for redelivery instead of losing it — never a dead-letter.
            log.warning(
                "Ollama unavailable — msg_id=%s stays unacked, backing off %.1fs",
                pending.msg_id,
                self._ollama_backoff_s,
            )
            time.sleep(self._ollama_backoff_s)
            self._ollama_backoff_s = min(self._ollama_backoff_s * 2, _OLLAMA_BACKOFF_MAX_S)
            return
        self._ollama_backoff_s = _OLLAMA_BACKOFF_INITIAL_S

        elapsed = time.monotonic() - start
        TRIAGE_DURATION.observe(elapsed)
        outcome = "dead_letter" if state["dead_letter"] is not None else "success"
        EVENTS_PROCESSED.labels(outcome=outcome).inc()

        self._bus.ack(pending.msg_id)
