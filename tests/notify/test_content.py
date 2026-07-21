from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, Severity, TriageContext, TriageRecord
from core.orchestrator.nodes.notify import NotifyDecision
from core.notify.content import NotificationContent, project_notification

_ALLOWLIST = {
    "severity", "classification", "confidence", "summary", "rationale",
    "src_ip_seen_before", "related_events_24h", "distinct_rules_from_src_24h",
    "events_last_10min", "src_in_allowlist", "suggested_actions",
    "matched_rule", "src_ip", "dst_ip", "sensor", "incident_group_key", "flags",
}


def _context(*, degraded: bool = False) -> TriageContext:
    return TriageContext(
        src_ip_seen_before=True,
        related_events_24h=47,
        distinct_rules_from_src_24h=1,
        events_last_10min=5,
        src_in_allowlist=False,
        matched_rule="2024358",
        lookup_degraded=degraded,
    )


def _record(*, degraded: bool = False) -> TriageRecord:
    return TriageRecord(
        alert_id="wz-1", event_id="e-1", classification=Classification.ALERT,
        confidence=0.91, severity=Severity.HIGH, summary="Nmap NSE scan",
        incident_group_key="9c2f4a8e0b21", context=_context(degraded=degraded),
        suggested_actions=["Block 203.0.113.5"], rationale="Repeated NSE activity",
        triaged_at=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
    )


def _event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-1", schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, tzinfo=UTC), source_module="wazuh",
        sensor="edge-01", source_alert_id="wz-1", event_type="NIDS",
        severity_hint="high", summary="scan", raw_ref="opensearch://x/wz-1",
        src_ip="203.0.113.5", dst_ip="10.0.0.1", rule_id="2024358",
    )


def _decision(flags: tuple[str, ...] = ("severity_floor",)) -> NotifyDecision:
    return NotifyDecision(should_notify=True, flags=flags, reason="new_session")


def test_content_field_set_is_exactly_the_allowlist() -> None:
    names = {f.name for f in dataclasses.fields(NotificationContent)}
    assert names == _ALLOWLIST


def test_projection_populates_from_event_and_context() -> None:
    c = project_notification(_record(), _event(), _decision())
    assert c.severity is Severity.HIGH
    assert c.classification is Classification.ALERT
    assert c.src_ip == "203.0.113.5"
    assert c.dst_ip == "10.0.0.1"
    assert c.sensor == "edge-01"
    assert c.matched_rule == "2024358"
    assert c.related_events_24h == 47
    assert c.suggested_actions == ("Block 203.0.113.5",)


def test_flags_carry_decision_flags() -> None:
    c = project_notification(_record(), _event(), _decision(flags=("severity_floor", "low_confidence")))
    assert "severity_floor" in c.flags
    assert "low_confidence" in c.flags


def test_context_degraded_flag_added_when_lookup_degraded() -> None:
    c = project_notification(_record(degraded=True), _event(), _decision())
    assert "context_degraded" in c.flags


def test_no_context_degraded_flag_when_not_degraded() -> None:
    c = project_notification(_record(degraded=False), _event(), _decision())
    assert "context_degraded" not in c.flags
