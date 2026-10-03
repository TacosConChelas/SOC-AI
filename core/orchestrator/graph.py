"""TriageGraph — LangGraph orchestrator wiring enrich → classify → group → persist → notify."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, TypedDict

from langgraph.graph import END, StateGraph

from core.bus.streams import RedisBus
from core.contracts.deadletter import DeadLetterRecord
from core.contracts.event import UnifiedEvent
from core.contracts.triage import (
    Severity,
    TriageContext,
    TriageModelOutput,
    TriageRecord,
)
from core.notify.content import NotificationContent, project_notification
from core.observability.metrics import DEADLETTER_TOTAL, NOTIFY_AGE_SUPPRESSED, NOTIFY_TOTAL
from core.orchestrator.nodes.classify import ClassifyOutcome, OllamaClient, classify_event
from core.orchestrator.nodes.enrich import enrich_event
from core.orchestrator.nodes.group import SessionState, SessionStore
from core.orchestrator.nodes.notify import NotifyDecision, notify_decision
from core.orchestrator.nodes.persist import persist_triage_record


class Notifier(Protocol):
    def send(self, content: NotificationContent) -> None: ...


class SystemNotifierProto(Protocol):
    def notify_dead_letter(self, record: DeadLetterRecord) -> None: ...
    def notify_degradation(self, event: UnifiedEvent) -> None: ...
    def notify_age_suppressed(self, event: UnifiedEvent) -> None: ...


class TriageState(TypedDict):
    event: UnifiedEvent
    context: TriageContext | None
    model_output: TriageModelOutput | None
    dead_letter: DeadLetterRecord | None
    session_state: SessionState | None
    triage_record: TriageRecord | None
    notify_decision: NotifyDecision | None


@dataclass
class TriageDeps:
    os_client: Any
    ollama_client: OllamaClient
    session_store: SessionStore
    pg_conn: Any
    dead_letter_bus: RedisBus
    notifier: Notifier
    system_notifier: SystemNotifierProto


def _derive_severity(event: UnifiedEvent) -> Severity:
    try:
        return Severity(event.severity_hint.lower())
    except ValueError:
        return Severity.LOW


class TriageGraph:
    def __init__(self, deps: TriageDeps) -> None:
        self._d = deps
        self._app = self._build()

    def run(self, event: UnifiedEvent) -> TriageState:
        initial: TriageState = {
            "event": event,
            "context": None,
            "model_output": None,
            "dead_letter": None,
            "session_state": None,
            "triage_record": None,
            "notify_decision": None,
        }
        result: TriageState = self._app.invoke(initial)
        return result

    # --- nodes ---

    def _enrich(self, state: TriageState) -> dict[str, Any]:
        ctx = enrich_event(state["event"], self._d.os_client, self._d.pg_conn)
        if ctx.lookup_degraded:
            self._d.system_notifier.notify_degradation(state["event"])
        return {"context": ctx}

    def _classify(self, state: TriageState) -> dict[str, Any]:
        assert state["context"] is not None
        outcome: ClassifyOutcome = classify_event(state["event"], state["context"], self._d.ollama_client)
        return {"model_output": outcome.model_output, "dead_letter": outcome.dead_letter}

    def _group(self, state: TriageState) -> dict[str, Any]:
        assert state["model_output"] is not None
        event = state["event"]
        session = self._d.session_store.fold(
            event,
            state["model_output"].classification,
            _derive_severity(event),
        )
        return {"session_state": session}

    def _persist(self, state: TriageState) -> dict[str, Any]:
        assert state["model_output"] is not None
        assert state["session_state"] is not None
        assert state["context"] is not None
        event = state["event"]
        record = TriageRecord(
            alert_id=event.source_alert_id,
            event_id=event.event_id,
            classification=state["model_output"].classification,
            confidence=state["model_output"].confidence,
            severity=_derive_severity(event),
            summary=state["model_output"].summary,
            incident_group_key=state["session_state"].incident_group_key,
            context=state["context"],
            suggested_actions=state["model_output"].suggested_actions,
            rationale=state["model_output"].rationale,
            triaged_at=datetime.now(UTC),
        )
        persist_triage_record(record, self._d.pg_conn)
        return {"triage_record": record}

    def _notify(self, state: TriageState) -> dict[str, Any]:
        assert state["triage_record"] is not None
        assert state["session_state"] is not None
        event = state["event"]
        decision = notify_decision(state["triage_record"], state["session_state"], event_timestamp=event.timestamp)
        if decision.should_notify:
            content = project_notification(state["triage_record"], event, decision)
            self._d.notifier.send(content)
            self._d.session_store.mark_notified(state["session_state"].session_key)
        elif decision.reason == "age_suppressed":
            NOTIFY_AGE_SUPPRESSED.labels(source_module=event.source_module).inc()
            self._d.system_notifier.notify_age_suppressed(event)
        NOTIFY_TOTAL.labels(decision="notified" if decision.should_notify else "suppressed").inc()
        return {"notify_decision": decision}

    def _handle_dead_letter(self, state: TriageState) -> dict[str, Any]:
        assert state["dead_letter"] is not None
        DEADLETTER_TOTAL.labels(reason=state["dead_letter"].reason.value).inc()
        self._d.dead_letter_bus.publish_dead_letter(state["dead_letter"])
        self._d.system_notifier.notify_dead_letter(state["dead_letter"])
        return {}

    # --- routing ---

    @staticmethod
    def _route_classify(state: TriageState) -> str:
        return "handle_dead_letter" if state["dead_letter"] else "group"

    # --- build ---

    def _build(self) -> Any:
        g: StateGraph[TriageState] = StateGraph(TriageState)
        g.add_node("enrich", self._enrich)
        g.add_node("classify", self._classify)
        g.add_node("group", self._group)
        g.add_node("persist", self._persist)
        g.add_node("notify", self._notify)
        g.add_node("handle_dead_letter", self._handle_dead_letter)

        g.set_entry_point("enrich")
        g.add_edge("enrich", "classify")
        g.add_conditional_edges(
            "classify",
            self._route_classify,
            {"group": "group", "handle_dead_letter": "handle_dead_letter"},
        )
        g.add_edge("group", "persist")
        g.add_edge("persist", "notify")
        g.add_edge("notify", END)
        g.add_edge("handle_dead_letter", END)

        return g.compile()
