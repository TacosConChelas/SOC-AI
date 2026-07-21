"""Persist node — TriageRecord → Postgres."""

from __future__ import annotations

import json
from typing import Any

from core.contracts.triage import TriageRecord


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
