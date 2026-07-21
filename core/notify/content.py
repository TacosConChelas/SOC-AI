"""Allowlist projection for incident notifications (3_Design_UI_UX.md §2.2, ADR-0004)."""

from __future__ import annotations

from dataclasses import dataclass

from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, Severity, TriageRecord
from core.orchestrator.nodes.notify import NotifyDecision


@dataclass(frozen=True)
class NotificationContent:
    severity: Severity
    classification: Classification
    confidence: float
    summary: str
    rationale: str
    src_ip_seen_before: bool
    related_events_24h: int
    distinct_rules_from_src_24h: int
    events_last_10min: int
    src_in_allowlist: bool
    suggested_actions: tuple[str, ...]
    matched_rule: str
    src_ip: str | None
    dst_ip: str | None
    sensor: str
    incident_group_key: str
    flags: tuple[str, ...]


def project_notification(
    record: TriageRecord, event: UnifiedEvent, decision: NotifyDecision
) -> NotificationContent:
    """Assemble the allowlist projection. The only place that decides what leaves the VPC."""
    ctx = record.context
    flags = decision.flags + (("context_degraded",) if ctx.lookup_degraded else ())
    return NotificationContent(
        severity=record.severity,
        classification=record.classification,
        confidence=record.confidence,
        summary=record.summary,
        rationale=record.rationale,
        src_ip_seen_before=ctx.src_ip_seen_before,
        related_events_24h=ctx.related_events_24h,
        distinct_rules_from_src_24h=ctx.distinct_rules_from_src_24h,
        events_last_10min=ctx.events_last_10min,
        src_in_allowlist=ctx.src_in_allowlist,
        suggested_actions=tuple(record.suggested_actions),
        matched_rule=ctx.matched_rule,
        src_ip=str(event.src_ip) if event.src_ip is not None else None,
        dst_ip=str(event.dst_ip) if event.dst_ip is not None else None,
        sensor=event.sensor,
        incident_group_key=record.incident_group_key,
        flags=flags,
    )
