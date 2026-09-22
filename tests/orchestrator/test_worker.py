"""Tests for the Worker — Redis Streams consumer loop."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from unittest.mock import MagicMock

import fakeredis

from core.bus.config import BusConfig
from core.bus.streams import BusError, RedisBus
from core.contracts.event import UnifiedEvent
from core.orchestrator.nodes.classify import OllamaUnavailableError
from core.orchestrator.worker import Worker


def _cfg() -> BusConfig:
    return BusConfig(block_ms=100, socket_timeout_s=1.0)


def _make_bus() -> tuple[RedisBus, fakeredis.FakeRedis]:
    r = fakeredis.FakeRedis(decode_responses=True)
    bus = RedisBus(client=r, config=_cfg())
    bus.ensure_group()
    return bus, r


def _event(rule_id: str = "1002") -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-001",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="edge-01",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="high",
        summary="Port scan",
        raw_ref="opensearch://soc-alerts/wz-1",
        src_ip="203.0.113.5",
        rule_id=rule_id,
    )


def _mock_graph(dead_letter: bool = False) -> MagicMock:
    g = MagicMock()
    g.run.return_value = {
        "event": _event(),
        "context": None,
        "model_output": None,
        "dead_letter": MagicMock() if dead_letter else None,
        "session_state": None,
        "triage_record": None if dead_letter else MagicMock(),
        "notify_decision": None,
    }
    return g


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def test_run_once_returns_true_when_event_available() -> None:
    bus, _ = _make_bus()
    bus.publish_event(_event())
    worker = Worker(bus=bus, graph=_mock_graph(), consumer_name="w0")
    assert worker.run_once() is True


def test_run_once_returns_false_on_empty_stream() -> None:
    bus, _ = _make_bus()
    worker = Worker(bus=bus, graph=_mock_graph(), consumer_name="w0")
    assert worker.run_once() is False


def test_run_once_calls_graph_with_correct_event() -> None:
    bus, _ = _make_bus()
    graph = _mock_graph()
    event = _event()
    bus.publish_event(event)
    Worker(bus=bus, graph=graph, consumer_name="w0").run_once()
    graph.run.assert_called_once()
    called_event = graph.run.call_args[0][0]
    assert called_event.event_id == event.event_id


def test_run_once_acks_after_processing() -> None:
    bus, r = _make_bus()
    bus.publish_event(_event())
    Worker(bus=bus, graph=_mock_graph(), consumer_name="w0").run_once()
    # PEL should be empty after ACK
    pending = r.xpending_range(bus._config.events_stream, bus._config.consumer_group, "-", "+", 10)
    assert pending == []


def test_run_once_dead_letter_still_acks() -> None:
    """A dead-letter path should still ACK so the message leaves the PEL."""
    bus, r = _make_bus()
    bus.publish_event(_event())
    Worker(bus=bus, graph=_mock_graph(dead_letter=True), consumer_name="w0").run_once()
    pending = r.xpending_range(bus._config.events_stream, bus._config.consumer_group, "-", "+", 10)
    assert pending == []


def test_run_once_processes_multiple_events_sequentially() -> None:
    bus, _ = _make_bus()
    graph = _mock_graph()
    for i in range(3):
        bus.publish_event(_event(rule_id=str(1000 + i)))
    worker = Worker(bus=bus, graph=graph, consumer_name="w0")
    for _ in range(3):
        worker.run_once()
    assert graph.run.call_count == 3


# ---------------------------------------------------------------------------
# claim_stale on startup
# ---------------------------------------------------------------------------


def test_run_claims_stale_before_polling() -> None:
    """Messages read but not acked by a crashed consumer are claimed on startup."""
    r = fakeredis.FakeRedis(decode_responses=True)
    cfg = _cfg()
    bus = RedisBus(client=r, config=cfg)
    bus.ensure_group()
    bus.publish_event(_event())

    # Read without acking — simulate a crash
    bus.read_one("crashed-worker")

    # New worker with min_idle_ms=0 so claim kicks in immediately
    cfg2 = BusConfig(block_ms=100, socket_timeout_s=1.0, claim_min_idle_ms=0)
    bus2 = RedisBus(client=r, config=cfg2)
    graph = _mock_graph()
    stop = threading.Event()
    stop.set()  # stop immediately after stale drain

    Worker(bus=bus2, graph=graph, consumer_name="new-worker").run(stop=stop)
    graph.run.assert_called_once()


# ---------------------------------------------------------------------------
# run() stop behavior
# ---------------------------------------------------------------------------


def test_run_exits_on_stop_event() -> None:
    bus, _ = _make_bus()
    graph = _mock_graph()
    stop = threading.Event()
    stop.set()
    # Should return almost immediately (no stale, stop already set)
    Worker(bus=bus, graph=graph).run(stop=stop)
    graph.run.assert_not_called()


def test_run_once_ollama_unavailable_does_not_ack() -> None:
    """ADR-0004 §2: a transient Ollama outage must never lose the message."""
    bus, r = _make_bus()
    bus.publish_event(_event())
    graph = MagicMock()
    graph.run.side_effect = OllamaUnavailableError("connection refused")
    worker = Worker(bus=bus, graph=graph, consumer_name="w0")

    worker.run_once()

    pending = r.xpending_range(bus._config.events_stream, bus._config.consumer_group, "-", "+", 10)
    assert len(pending) == 1


def test_run_once_ollama_unavailable_backs_off_exponentially(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bus, _ = _make_bus()
    bus.publish_event(_event())
    bus.publish_event(_event())
    graph = MagicMock()
    graph.run.side_effect = OllamaUnavailableError("down")
    worker = Worker(bus=bus, graph=graph, consumer_name="w0")

    sleeps: list[float] = []
    monkeypatch.setattr("core.orchestrator.worker.time.sleep", lambda s: sleeps.append(s))

    worker.run_once()
    worker.run_once()

    assert sleeps == [1.0, 2.0]


def test_run_once_ollama_backoff_caps_at_30s(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bus, _ = _make_bus()
    for _ in range(8):
        bus.publish_event(_event())
    graph = MagicMock()
    graph.run.side_effect = OllamaUnavailableError("down")
    worker = Worker(bus=bus, graph=graph, consumer_name="w0")

    sleeps: list[float] = []
    monkeypatch.setattr("core.orchestrator.worker.time.sleep", lambda s: sleeps.append(s))

    for _ in range(8):
        worker.run_once()

    assert sleeps[-1] == 30.0
    assert max(sleeps) == 30.0


def test_run_once_ollama_backoff_resets_after_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bus, _ = _make_bus()
    for _ in range(3):
        bus.publish_event(_event())
    graph = MagicMock()
    graph.run.side_effect = [
        OllamaUnavailableError("down"),
        _mock_graph().run.return_value,
        OllamaUnavailableError("down"),
    ]
    worker = Worker(bus=bus, graph=graph, consumer_name="w0")

    sleeps: list[float] = []
    monkeypatch.setattr("core.orchestrator.worker.time.sleep", lambda s: sleeps.append(s))

    worker.run_once()  # fails -> sleep(1.0), backoff -> 2.0
    worker.run_once()  # succeeds -> acks, backoff resets -> 1.0
    worker.run_once()  # fails again -> sleep(1.0), not 4.0

    assert sleeps == [1.0, 1.0]


def test_run_once_dead_letter_from_parse_failure_still_acks() -> None:
    """Non-connectivity dead-letters (e.g. parse_failure) must keep acking —
    only OllamaUnavailableError skips the ack."""
    bus, r = _make_bus()
    bus.publish_event(_event())
    Worker(bus=bus, graph=_mock_graph(dead_letter=True), consumer_name="w0").run_once()
    pending = r.xpending_range(bus._config.events_stream, bus._config.consumer_group, "-", "+", 10)
    assert pending == []


# ---------------------------------------------------------------------------
# BusError — run() backs off instead of crashing (decisions.md tasks 21 & 42)
# ---------------------------------------------------------------------------


def test_run_bus_error_does_not_crash_and_backs_off(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bus = MagicMock()
    bus.claim_stale.return_value = []
    stop = threading.Event()
    calls = {"n": 0}

    def flaky_read_one(consumer: str) -> None:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise BusError("connection refused")
        stop.set()
        return None

    bus.read_one.side_effect = flaky_read_one
    worker = Worker(bus=bus, graph=_mock_graph(), consumer_name="w0")

    sleeps: list[float] = []
    monkeypatch.setattr("core.orchestrator.worker.time.sleep", lambda s: sleeps.append(s))

    worker.run(stop=stop)  # must not raise

    assert sleeps == [1.0, 2.0]


def test_run_bus_error_backoff_resets_after_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bus = MagicMock()
    bus.claim_stale.return_value = []
    stop = threading.Event()
    calls = {"n": 0}

    def flaky_read_one(consumer: str) -> None:
        calls["n"] += 1
        if calls["n"] in (1, 3):
            raise BusError("connection refused")
        if calls["n"] == 4:
            stop.set()
            return None
        return None  # call 2 succeeds — resets backoff before call 3 fails again

    bus.read_one.side_effect = flaky_read_one
    worker = Worker(bus=bus, graph=_mock_graph(), consumer_name="w0")

    sleeps: list[float] = []
    monkeypatch.setattr("core.orchestrator.worker.time.sleep", lambda s: sleeps.append(s))

    worker.run(stop=stop)

    assert sleeps == [1.0, 1.0]  # not [1.0, 2.0] — reset by the success on call 2


def test_run_processes_events_until_stopped() -> None:
    bus, _ = _make_bus()
    graph = _mock_graph()
    for _ in range(2):
        bus.publish_event(_event())

    stop = threading.Event()
    processed: list[int] = []

    original_run_once = Worker.run_once

    def counting_run_once(self: Worker) -> bool:
        result = original_run_once(self)
        if result:
            processed.append(1)
        if len(processed) >= 2:
            stop.set()
        return result

    Worker.run_once = counting_run_once  # type: ignore[method-assign]
    try:
        Worker(bus=bus, graph=graph).run(stop=stop)
    finally:
        Worker.run_once = original_run_once  # type: ignore[method-assign]

    assert len(processed) == 2
