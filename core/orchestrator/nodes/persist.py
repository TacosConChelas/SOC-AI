"""Persist node — TriageRecord → Postgres; DeadLetterRecord → Redis dead-letter stream."""

from __future__ import annotations

import json
from typing import Any

import redis

from core.contracts.deadletter import DeadLetterRecord
from core.contracts.triage import TriageRecord

_DEAD_LETTER_STREAM = "triage:deadletter"


def persist_triage_record(record: TriageRecord, conn: Any) -> None:
    """INSERT a TriageRecord into triage_records and commit.

    conn is a psycopg.Connection (typed as Any to avoid import-time stub issues).
    """
    conn.execute(
        """
        INSERT INTO triage_records (
            alert_id, event_id, classification, confidence, severity,
            summary, incident_group_key, context, suggested_actions,
            rationale, triaged_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s)
        """,
        (
            record.alert_id,
            record.event_id,
            record.classification,
            record.confidence,
            record.severity,
            record.summary,
            record.incident_group_key,
            json.dumps(record.context.model_dump()),
            json.dumps(record.suggested_actions),
            record.rationale,
            record.triaged_at,
        ),
    )
    conn.commit()


def publish_dead_letter(record: DeadLetterRecord, redis_client: redis.Redis) -> None:
    """XADD a DeadLetterRecord to the triage:deadletter stream."""
    redis_client.xadd(
        _DEAD_LETTER_STREAM,
        {
            "alert_id": record.alert_id,
            "event_id": record.event_id,
            "source_module": record.source_module,
            "sensor": record.sensor,
            "severity": record.severity,
            "reason": record.reason,
            "retry_count": str(record.retry_count),
            "dead_lettered_at": record.dead_lettered_at.isoformat(),
            "detail": record.detail,
        },
    )
