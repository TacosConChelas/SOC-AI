"""Tests for the TriageGraph orchestrator — mocked dependencies."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import fakeredis

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, Severity
from core.notify.content import NotificationContent
from core.orchestrator.graph import TriageDeps, TriageGraph
from core.orchestrator.nodes.classify import OllamaClient
from core.orchestrator.nodes.group import SessionStore

_VALID_LLM_JSON = (
    '{"classification": "alert", "confidence": 0.91, '
    '"summary": "Port scan detected", '
    '"suggested_actions": ["block ip"], '
    '"rationale": "Multiple ports probed in short window"}'
)

_OS_RESPONSE = {
    "hits": {"total": {"value": 5}},
    "aggregations": {"distinct_rules": {"value": 2}},
}


def _event(severity_hint: str = "high") -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-001",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="edge-01",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint=severity_hint,
        summary="Port scan",
        raw_ref="opensearch://soc-alerts/wz-1",
        src_ip="203.0.113.5",
        rule_id="1002",
    )


def _make_deps(*, llm_response: str = _VALID_LLM_JSON) -> TriageDeps:
    os_client = MagicMock()
    os_client.search.return_value = _OS_RESPONSE

    ollama = MagicMock(spec=OllamaClient)
    ollama.chat.return_value = llm_response

    dl_redis = fakeredis.FakeRedis(decode_responses=True)
    return TriageDeps(
        os_client=os_client,
        ollama_client=ollama,
        session_store=SessionStore(client=fakeredis.FakeRedis(decode_responses=True), gap_seconds=300),
        pg_conn=MagicMock(),
        dead_letter_bus=RedisBus(client=dl_redis, config=BusConfig(block_ms=100, socket_timeout_s=1.0)),
        notifier=MagicMock(),
        system_notifier=MagicMock(),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_happy_path_persists_triage_record() -> None:
    deps = _make_deps()
    TriageGraph(deps).run(_event())
    deps.pg_conn.execute.assert_called_once()
    deps.pg_conn.commit.assert_called_once()


def test_happy_path_triage_record_in_final_state() -> None:
    deps = _make_deps()
    state = TriageGraph(deps).run(_event())
    assert state["triage_record"] is not None
    assert state["triage_record"].classification == Classification.ALERT


def test_severity_from_event_not_model() -> None:
    """ADR-0001: severity comes from severity_hint on the event, never from the LLM."""
    deps = _make_deps()
    state = TriageGraph(deps).run(_event(severity_hint="critical"))
    assert state["triage_record"] is not None
    assert state["triage_record"].severity == Severity.CRITICAL


def test_unknown_severity_hint_falls_back_to_low() -> None:
    deps = _make_deps()
    state = TriageGraph(deps).run(_event(severity_hint="banana"))
    assert state["triage_record"] is not None
    assert state["triage_record"].severity == Severity.LOW


def test_happy_path_notifier_called() -> None:
    deps = _make_deps()
    TriageGraph(deps).run(_event())
    deps.notifier.send.assert_called_once()


def test_second_alert_same_session_suppresses_notification() -> None:
    """Campaign: session notified on first alert; second alert folds silently."""
    deps = _make_deps()
    graph = TriageGraph(deps)
    event = _event()
    graph.run(event)
    state2 = graph.run(event)
    assert deps.notifier.send.call_count == 1
    assert state2["notify_decision"] is not None
    assert state2["notify_decision"].reason == "suppressed"


class _CapturingNotifier:
    def __init__(self) -> None:
        self.sent: list[NotificationContent] = []

    def send(self, content: NotificationContent) -> None:
        self.sent.append(content)


def test_notify_receives_projected_content() -> None:
    notifier = _CapturingNotifier()
    os_client = MagicMock()
    os_client.search.return_value = _OS_RESPONSE
    ollama = MagicMock(spec=OllamaClient)
    ollama.chat.return_value = _VALID_LLM_JSON
    dl = fakeredis.FakeRedis(decode_responses=True)
    deps = TriageDeps(
        os_client=os_client,
        ollama_client=ollama,
        session_store=SessionStore(client=fakeredis.FakeRedis(decode_responses=True), gap_seconds=300),
        pg_conn=MagicMock(),
        dead_letter_bus=RedisBus(client=dl, config=BusConfig(block_ms=100, socket_timeout_s=1.0)),
        notifier=notifier,
        system_notifier=MagicMock(),
    )
    TriageGraph(deps).run(_event())
    assert len(notifier.sent) == 1
    content = notifier.sent[0]
    assert isinstance(content, NotificationContent)
    assert content.severity is Severity.HIGH
    assert content.src_ip == "203.0.113.5"


def test_enrich_context_passed_to_model() -> None:
    """context ends up in the TriageRecord.context field."""
    deps = _make_deps()
    state = TriageGraph(deps).run(_event())
    assert state["triage_record"] is not None
    assert state["triage_record"].context is not None
    # OS mock returned 5 hits for all queries → related_events_24h = 5
    assert state["triage_record"].context.related_events_24h == 5


# ---------------------------------------------------------------------------
# Dead-letter path
# ---------------------------------------------------------------------------


def test_dead_letter_no_db_write() -> None:
    deps = _make_deps(llm_response="not valid json")
    TriageGraph(deps).run(_event())
    deps.pg_conn.execute.assert_not_called()


def test_dead_letter_published_to_stream() -> None:
    deps = _make_deps(llm_response="not valid json")
    TriageGraph(deps).run(_event())
    assert len(deps.dead_letter_bus._client.xrange("soc:deadletter")) == 1


def test_dead_letter_no_notification() -> None:
    deps = _make_deps(llm_response="not valid json")
    TriageGraph(deps).run(_event())
    deps.notifier.send.assert_not_called()


def test_dead_letter_triage_record_is_none() -> None:
    deps = _make_deps(llm_response="not valid json")
    state = TriageGraph(deps).run(_event())
    assert state["triage_record"] is None


# ---------------------------------------------------------------------------
# Enrich degraded path
# ---------------------------------------------------------------------------


def test_enrich_degraded_pipeline_still_completes() -> None:
    """OpenSearch down → zeroed context → classify still runs → pipeline finishes."""
    deps = _make_deps()
    deps.os_client.search.side_effect = Exception("OS down")
    state = TriageGraph(deps).run(_event())
    assert state["triage_record"] is not None
    assert state["triage_record"].context.lookup_degraded is True


def test_enrich_degraded_fires_system_notifier() -> None:
    deps = _make_deps()
    deps.os_client.search.side_effect = Exception("OS down")
    TriageGraph(deps).run(_event())
    deps.system_notifier.notify_degradation.assert_called_once()


# ---------------------------------------------------------------------------
# System notifier — dead-letter path
# ---------------------------------------------------------------------------


def test_dead_letter_fires_system_notifier() -> None:
    deps = _make_deps(llm_response="not valid json")
    TriageGraph(deps).run(_event())
    deps.system_notifier.notify_dead_letter.assert_called_once()
