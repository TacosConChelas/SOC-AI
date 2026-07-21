"""Tests for the persist node — mocks psycopg connection and Redis client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import fakeredis

from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord
from core.contracts.triage import (
    Classification,
    Severity,
    TriageContext,
    TriageRecord,
)
from core.orchestrator.nodes.persist import (
    _DEAD_LETTER_STREAM,
    persist_triage_record,
    publish_dead_letter,
)


def _context() -> TriageContext:
    return TriageContext(
        src_ip_seen_before=True,
        related_events_24h=5,
        distinct_rules_from_src_24h=2,
        events_last_10min=3,
        src_in_allowlist=False,
        matched_rule="1002",
    )


def _triage_record() -> TriageRecord:
    return TriageRecord(
        alert_id="wz-1",
        event_id="e-001",
        classification=Classification.ALERT,
        confidence=0.92,
        severity=Severity.HIGH,
        summary="Port scan detected",
        incident_group_key="inc-abc-123",
        context=_context(),
        suggested_actions=["block ip", "review logs"],
        rationale="Multiple ports probed in short window",
        triaged_at=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
    )


def _dead_letter_record() -> DeadLetterRecord:
    return DeadLetterRecord(
        alert_id="wz-2",
        event_id="e-002",
        source_module="wazuh",
        sensor="h1",
        severity="critical",
        reason=DeadLetterReason.PARSE_FAILURE,
        retry_count=2,
        dead_lettered_at=datetime(2026, 7, 20, 12, 5, 0, tzinfo=UTC),
        detail="ValidationError after 2 attempts: ValueError",
    )


# ---------------------------------------------------------------------------
# persist_triage_record
# ---------------------------------------------------------------------------


def test_persist_calls_execute_and_commit() -> None:
    conn = MagicMock()
    record = _triage_record()
    persist_triage_record(record, conn)
    conn.execute.assert_called_once()
    conn.commit.assert_called_once()


def test_persist_sql_contains_insert() -> None:
    conn = MagicMock()
    persist_triage_record(_triage_record(), conn)
    sql: str = conn.execute.call_args[0][0]
    assert "INSERT INTO triage_records" in sql


def test_persist_passes_correct_values() -> None:
    conn = MagicMock()
    record = _triage_record()
    persist_triage_record(record, conn)

    params = conn.execute.call_args[0][1]
    assert params[0] == record.alert_id
    assert params[1] == record.event_id
    assert params[2] == record.classification
    assert params[3] == record.confidence
    assert params[4] == record.severity
    assert params[5] == record.summary
    assert params[6] == record.incident_group_key
    # context and suggested_actions are JSON-serialized
    assert json.loads(params[7]) == record.context.model_dump()
    assert json.loads(params[8]) == record.suggested_actions
    assert params[9] == record.rationale
    assert params[10] == record.triaged_at


def test_persist_context_is_valid_json() -> None:
    conn = MagicMock()
    persist_triage_record(_triage_record(), conn)
    params = conn.execute.call_args[0][1]
    # must not raise
    parsed = json.loads(params[7])
    assert isinstance(parsed, dict)


def test_persist_suggested_actions_is_json_list() -> None:
    conn = MagicMock()
    persist_triage_record(_triage_record(), conn)
    params = conn.execute.call_args[0][1]
    parsed = json.loads(params[8])
    assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# publish_dead_letter
# ---------------------------------------------------------------------------


def test_dead_letter_goes_to_correct_stream() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    publish_dead_letter(_dead_letter_record(), r)
    entries = r.xrange(_DEAD_LETTER_STREAM)
    assert len(entries) == 1


def test_dead_letter_fields_are_present() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    record = _dead_letter_record()
    publish_dead_letter(record, r)
    _, fields = r.xrange(_DEAD_LETTER_STREAM)[0]
    assert fields["alert_id"] == record.alert_id
    assert fields["event_id"] == record.event_id
    assert fields["reason"] == record.reason
    assert fields["retry_count"] == str(record.retry_count)
    assert fields["detail"] == record.detail


def test_dead_letter_dead_lettered_at_is_iso() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    record = _dead_letter_record()
    publish_dead_letter(record, r)
    _, fields = r.xrange(_DEAD_LETTER_STREAM)[0]
    # must parse back cleanly
    parsed = datetime.fromisoformat(fields["dead_lettered_at"])
    assert parsed == record.dead_lettered_at


def test_dead_letter_multiple_records_accumulate() -> None:
    r = fakeredis.FakeRedis(decode_responses=True)
    for _ in range(3):
        publish_dead_letter(_dead_letter_record(), r)
    assert len(r.xrange(_DEAD_LETTER_STREAM)) == 3
