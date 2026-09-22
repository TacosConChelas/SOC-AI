"""Allowlist projection for system notifications: dead-letter and enrichment degradation."""

from __future__ import annotations

from dataclasses import dataclass

from core.contracts.deadletter import DeadLetterRecord
from core.contracts.event import UnifiedEvent


@dataclass(frozen=True)
class SystemNotification:
    kind: str
    sensor: str
    severity: str
    reason: str
    retry_count: int | None
    detail: str | None


def project_dead_letter(record: DeadLetterRecord) -> SystemNotification:
    return SystemNotification(
        kind="dead_letter",
        sensor=record.sensor,
        severity=record.severity,
        reason=record.reason.value,
        retry_count=record.retry_count,
        detail=record.detail,
    )


def project_degradation(event: UnifiedEvent) -> SystemNotification:
    return SystemNotification(
        kind="enrichment_degraded",
        sensor=event.sensor,
        severity=event.severity_hint,
        reason="enrichment_degraded",
        retry_count=None,
        detail=None,
    )


def project_age_suppressed(event: UnifiedEvent) -> SystemNotification:
    """ADR-0004 Enmienda 2026-08 (D-16): fail-loud, coalesced notice for age-suppressed events."""
    return SystemNotification(
        kind="age_suppressed",
        sensor=event.sensor,
        severity=event.severity_hint,
        reason="age_suppressed",
        retry_count=None,
        detail=None,
    )
