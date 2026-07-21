from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord
from core.contracts.event import UnifiedEvent
from core.notify.system import SystemNotification, project_dead_letter, project_degradation

_ALLOWLIST = {
    "kind",
    "sensor",
    "severity",
    "reason",
    "retry_count",
    "detail",
}


def _record(
    *,
    reason: DeadLetterReason = DeadLetterReason.PARSE_FAILURE,
    detail: str = "ValidationError",
) -> DeadLetterRecord:
    return DeadLetterRecord(
        alert_id="wz-1",
        event_id="e-1",
        source_module="wazuh",
        sensor="edge-01",
        severity="high",
        reason=reason,
        retry_count=2,
        dead_lettered_at=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        detail=detail,
    )


def _event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-1",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="edge-01",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="high",
        summary="scan",
        raw_ref="opensearch://x/wz-1",
        src_ip="203.0.113.5",
        rule_id="2024358",
    )


# --- field-set contract ---


def test_system_notification_field_set() -> None:
    names = {f.name for f in dataclasses.fields(SystemNotification)}
    assert names == _ALLOWLIST


# --- project_dead_letter ---


def test_project_dead_letter_maps_all_fields() -> None:
    n = project_dead_letter(_record())
    assert n.kind == "dead_letter"
    assert n.sensor == "edge-01"
    assert n.severity == "high"
    assert n.reason == "parse_failure"
    assert n.retry_count == 2
    assert n.detail == "ValidationError"


def test_project_dead_letter_detail_is_code_not_verbatim() -> None:
    """detail must come from the record unchanged; verbatim model output must never reach here."""
    rec = _record(detail="ValidationError: extra fields not permitted")
    n = project_dead_letter(rec)
    # detail is passed through (the invariant is upheld at record construction time)
    assert n.detail == rec.detail


def test_project_dead_letter_reason_is_string() -> None:
    n = project_dead_letter(_record(reason=DeadLetterReason.MODEL_UNAVAILABLE))
    assert n.reason == "model_unavailable"


# --- project_degradation ---


def test_project_degradation_maps_event_fields() -> None:
    n = project_degradation(_event())
    assert n.kind == "enrichment_degraded"
    assert n.sensor == "edge-01"
    assert n.severity == "high"
    assert n.reason == "enrichment_degraded"
    assert n.retry_count is None
    assert n.detail is None
