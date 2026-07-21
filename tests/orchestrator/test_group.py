"""Tests for the group node — session-based incident grouping (fakeredis[lua])."""

from datetime import UTC, datetime

import fakeredis
import pytest

from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, Severity
from core.orchestrator.nodes.group import SessionStore


def _event(src_ip: str | None = "203.0.113.5", rule_id: str = "1002", sensor: str = "h1") -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-001",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor=sensor,
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="medium",
        summary="Test",
        raw_ref="opensearch://soc-alerts/wz-1",
        src_ip=src_ip,
        rule_id=rule_id,
    )


@pytest.fixture()
def store() -> SessionStore:
    client = fakeredis.FakeRedis(decode_responses=True)
    return SessionStore(client=client, gap_seconds=300)


# ---------------------------------------------------------------------------
# Session opening (new session)
# ---------------------------------------------------------------------------


def test_first_alert_opens_new_session(store: SessionStore) -> None:
    state = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert state.is_new_session is True
    assert isinstance(state.incident_group_key, str)
    assert len(state.incident_group_key) > 0


def test_second_alert_same_sig_folds_into_session(store: SessionStore) -> None:
    first = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    second = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert second.is_new_session is False
    assert second.incident_group_key == first.incident_group_key


def test_session_key_is_stable_across_folds(store: SessionStore) -> None:
    keys = [store.fold(_event(), Classification.ALERT, Severity.MEDIUM).incident_group_key for _ in range(5)]
    assert len(set(keys)) == 1


# ---------------------------------------------------------------------------
# Session signature
# ---------------------------------------------------------------------------


def test_different_rule_different_session(store: SessionStore) -> None:
    a = store.fold(_event(rule_id="1001"), Classification.ALERT, Severity.HIGH)
    b = store.fold(_event(rule_id="1002"), Classification.ALERT, Severity.HIGH)
    assert a.incident_group_key != b.incident_group_key


def test_different_src_ip_different_session(store: SessionStore) -> None:
    a = store.fold(_event(src_ip="1.2.3.4"), Classification.ALERT, Severity.HIGH)
    b = store.fold(_event(src_ip="5.6.7.8"), Classification.ALERT, Severity.HIGH)
    assert a.incident_group_key != b.incident_group_key


def test_classification_not_part_of_session_sig(store: SessionStore) -> None:
    """Oscillating classification must not split the session (ADR-0002)."""
    a = store.fold(_event(), Classification.NOISE, Severity.LOW)
    b = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert a.incident_group_key == b.incident_group_key


# ---------------------------------------------------------------------------
# Host events — sensor fallback
# ---------------------------------------------------------------------------


def test_host_event_uses_sensor_as_key(store: SessionStore) -> None:
    a = store.fold(_event(src_ip=None, sensor="host-01"), Classification.INFORMATIONAL, Severity.LOW)
    b = store.fold(_event(src_ip=None, sensor="host-01"), Classification.INFORMATIONAL, Severity.LOW)
    assert b.incident_group_key == a.incident_group_key
    assert b.is_new_session is False


def test_host_event_different_sensor_different_session(store: SessionStore) -> None:
    a = store.fold(_event(src_ip=None, sensor="host-01"), Classification.INFORMATIONAL, Severity.LOW)
    b = store.fold(_event(src_ip=None, sensor="host-02"), Classification.INFORMATIONAL, Severity.LOW)
    assert a.incident_group_key != b.incident_group_key


# ---------------------------------------------------------------------------
# Intra-session escalation
# ---------------------------------------------------------------------------


def test_escalation_informational_to_alert(store: SessionStore) -> None:
    """Session opened as informational; subsequent alert must set escalated=True."""
    store.fold(_event(), Classification.INFORMATIONAL, Severity.LOW)
    state = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert state.escalated is True


def test_no_escalation_same_classification(store: SessionStore) -> None:
    store.fold(_event(), Classification.ALERT, Severity.HIGH)
    state = store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert state.escalated is False


def test_no_escalation_downgrade(store: SessionStore) -> None:
    """alert → informational is not escalation."""
    store.fold(_event(), Classification.ALERT, Severity.HIGH)
    state = store.fold(_event(), Classification.INFORMATIONAL, Severity.LOW)
    assert state.escalated is False


# ---------------------------------------------------------------------------
# Gap / TTL
# ---------------------------------------------------------------------------


def test_expired_session_opens_new_session(store: SessionStore) -> None:
    """Session with gap_seconds=1 expires; next alert opens a new session."""
    fast_store = SessionStore(client=fakeredis.FakeRedis(decode_responses=True), gap_seconds=1)
    first = fast_store.fold(_event(), Classification.ALERT, Severity.HIGH)
    import time

    time.sleep(1.1)
    second = fast_store.fold(_event(), Classification.ALERT, Severity.HIGH)
    assert second.is_new_session is True
    assert second.incident_group_key != first.incident_group_key
