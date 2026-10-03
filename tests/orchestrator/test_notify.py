"""Tests for the notify decision tree (flow doc §3 + ADR-0004)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.contracts.triage import (
    Classification,
    Severity,
    TriageContext,
    TriageRecord,
)
from core.orchestrator.nodes.group import SessionState
from core.orchestrator.nodes.notify import notify_decision

# Fixed event_timestamp/now pair for tests that exercise levels 1-4 and don't care
# about age suppression itself: 30 minutes apart, well inside the default 2h window,
# so these tests never depend on the wall clock (event_timestamp is a required param).
_EVENT_TS = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
_NOW_TS = datetime(2026, 7, 20, 12, 30, 0, tzinfo=UTC)


def _session(
    *,
    is_new: bool = True,
    was_notified: bool = False,
    escalated: bool = False,
) -> SessionState:
    return SessionState(
        incident_group_key="inc-001",
        is_new_session=is_new,
        escalated=escalated,
        session_was_notified=was_notified,
        session_key="session:abc",
    )


def _record(
    *,
    severity: Severity = Severity.MEDIUM,
    classification: Classification = Classification.ALERT,
    confidence: float = 0.9,
) -> TriageRecord:
    return TriageRecord(
        alert_id="wz-1",
        event_id="e-001",
        classification=classification,
        confidence=confidence,
        severity=severity,
        summary="Test alert",
        incident_group_key="inc-001",
        context=TriageContext(
            src_ip_seen_before=False,
            related_events_24h=0,
            distinct_rules_from_src_24h=0,
            events_last_10min=0,
            src_in_allowlist=False,
            finding_seen_before=False,
            matched_rule="1002",
        ),
        suggested_actions=["check logs"],
        rationale="Test rationale",
        triaged_at=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Level 0 — Event age cutoff (ADR-0004 Enmienda 2026-08, D-16/D-20)
# ---------------------------------------------------------------------------


def test_old_event_suppressed_even_if_critical() -> None:
    """Age is the sole documented exception to 'every critical always notifies'."""
    now = datetime(2026, 7, 20, 14, 0, 0, tzinfo=UTC)
    old_timestamp = datetime(2026, 7, 20, 11, 0, 0, tzinfo=UTC)  # 3h old
    d = notify_decision(
        _record(severity=Severity.CRITICAL, classification=Classification.ALERT, confidence=0.99),
        _session(),
        event_timestamp=old_timestamp,
        max_event_age_s=2 * 3600,
        now=now,
    )
    assert d.should_notify is False
    assert d.reason == "age_suppressed"


def test_event_within_age_range_proceeds_to_next_level() -> None:
    now = datetime(2026, 7, 20, 14, 0, 0, tzinfo=UTC)
    recent_timestamp = datetime(2026, 7, 20, 13, 0, 0, tzinfo=UTC)  # 1h old
    d = notify_decision(
        _record(severity=Severity.CRITICAL, classification=Classification.ALERT, confidence=0.99),
        _session(),
        event_timestamp=recent_timestamp,
        max_event_age_s=2 * 3600,
        now=now,
    )
    assert d.should_notify is True
    assert "severity_floor" in d.flags


def test_event_within_window_does_not_trigger_age_suppression() -> None:
    """event_timestamp is required, but a fresh event never hits the age-suppression branch."""
    d = notify_decision(_record(), _session(), event_timestamp=_EVENT_TS, now=_NOW_TS)
    assert d.reason != "age_suppressed"


# ---------------------------------------------------------------------------
# Level 1 — Severity floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sev", [Severity.HIGH, Severity.CRITICAL])
def test_severity_floor_forces_candidate(sev: Severity) -> None:
    d = notify_decision(
        _record(severity=sev, classification=Classification.NOISE),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is True
    assert "severity_floor" in d.flags


def test_severity_floor_noise_adds_false_positive_flag() -> None:
    d = notify_decision(
        _record(severity=Severity.HIGH, classification=Classification.NOISE),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert "false_positive_candidate" in d.flags


def test_severity_floor_alert_no_false_positive_flag() -> None:
    d = notify_decision(
        _record(severity=Severity.HIGH, classification=Classification.ALERT),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert "false_positive_candidate" not in d.flags


def test_severity_floor_informational_no_false_positive_flag() -> None:
    d = notify_decision(
        _record(severity=Severity.CRITICAL, classification=Classification.INFORMATIONAL),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert "false_positive_candidate" not in d.flags


# ---------------------------------------------------------------------------
# Level 2 — Confidence gate
# ---------------------------------------------------------------------------


def test_low_confidence_forces_candidate() -> None:
    d = notify_decision(
        _record(severity=Severity.MEDIUM, classification=Classification.INFORMATIONAL, confidence=0.5),
        _session(),
        confidence_threshold=0.7,
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is True
    assert "low_confidence" in d.flags


def test_confidence_at_threshold_does_not_trigger_gate() -> None:
    """Boundary: confidence == threshold is NOT below threshold."""
    d = notify_decision(
        _record(severity=Severity.LOW, classification=Classification.NOISE, confidence=0.7),
        _session(),
        confidence_threshold=0.7,
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is False
    assert "low_confidence" not in d.flags


def test_confidence_gate_not_triggered_when_severity_floor_active() -> None:
    """Floor takes priority; gate flag must not appear."""
    d = notify_decision(
        _record(severity=Severity.HIGH, classification=Classification.NOISE, confidence=0.1),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert "severity_floor" in d.flags
    assert "low_confidence" not in d.flags


# ---------------------------------------------------------------------------
# Level 3 — Model judgment
# ---------------------------------------------------------------------------


def test_alert_classification_is_candidate() -> None:
    d = notify_decision(
        _record(severity=Severity.LOW, classification=Classification.ALERT, confidence=0.9),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is True
    assert d.reason == "new_session"


def test_informational_without_floor_or_gate_suppressed() -> None:
    d = notify_decision(
        _record(severity=Severity.LOW, classification=Classification.INFORMATIONAL, confidence=0.9),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is False
    assert d.reason == "not_candidate"


def test_noise_medium_severity_suppressed() -> None:
    d = notify_decision(
        _record(severity=Severity.MEDIUM, classification=Classification.NOISE, confidence=0.95),
        _session(),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is False
    assert d.reason == "not_candidate"


# ---------------------------------------------------------------------------
# Level 4 — Session granularity
# ---------------------------------------------------------------------------


def test_new_session_notifies_with_reason_new_session() -> None:
    d = notify_decision(_record(), _session(is_new=True), event_timestamp=_EVENT_TS, now=_NOW_TS)
    assert d.should_notify is True
    assert d.reason == "new_session"


def test_existing_unnotified_session_escalates() -> None:
    """Session opened silently (informational); now an alert arrives."""
    d = notify_decision(
        _record(),
        _session(is_new=False, was_notified=False),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is True
    assert d.reason == "intra_session_escalation"


def test_already_notified_session_suppresses() -> None:
    """Campaign: session notified on first alert; subsequent alerts fold."""
    d = notify_decision(
        _record(),
        _session(is_new=False, was_notified=True),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is False
    assert d.reason == "suppressed"


def test_suppressed_session_still_carries_floor_flag() -> None:
    """Even when suppressed, the flags are preserved for metrics/logging."""
    d = notify_decision(
        _record(severity=Severity.HIGH),
        _session(is_new=False, was_notified=True),
        event_timestamp=_EVENT_TS,
        now=_NOW_TS,
    )
    assert d.should_notify is False
    assert "severity_floor" in d.flags


# ---------------------------------------------------------------------------
# mark_notified integration — group + notify
# ---------------------------------------------------------------------------


def test_mark_notified_prevents_second_notification() -> None:
    import fakeredis

    from core.orchestrator.nodes.group import SessionStore

    r = fakeredis.FakeRedis(decode_responses=True)
    store = SessionStore(client=r, gap_seconds=300)

    from core.contracts.event import UnifiedEvent

    event = UnifiedEvent(
        event_id="e-1",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="h1",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="high",
        summary="Test",
        raw_ref="opensearch://soc-alerts/wz-1",
        src_ip=None,
        rule_id="1002",
    )
    rec = _record(severity=Severity.HIGH)

    state1 = store.fold(event, Classification.ALERT, Severity.HIGH)
    d1 = notify_decision(rec, state1, event_timestamp=event.timestamp, now=_NOW_TS)
    assert d1.should_notify is True

    # Simulate: notification sent → mark notified
    store.mark_notified(state1.session_key)

    state2 = store.fold(event, Classification.ALERT, Severity.HIGH)
    d2 = notify_decision(rec, state2, event_timestamp=event.timestamp, now=_NOW_TS)
    assert d2.should_notify is False
    assert d2.reason == "suppressed"
