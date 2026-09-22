"""Notify node — 5-level decision tree (ADR-0004, flow doc §3; age cutoff: Enmienda 2026-08)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

from core.contracts.triage import Classification, Severity, TriageRecord
from core.orchestrator.nodes.group import SessionState

_SEVERITY_FLOOR = frozenset({Severity.HIGH, Severity.CRITICAL})

_DEFAULT_CONFIDENCE_THRESHOLD = float(os.getenv("SOC_CONFIDENCE_THRESHOLD", "0.7"))

# PD-005 starting value per ADR-0004 Enmienda 2026-08 / decisions.md task 21: 2 hours.
_DEFAULT_MAX_EVENT_AGE_S = float(os.getenv("SOC_NOTIFY_MAX_EVENT_AGE_S", str(2 * 3600)))


@dataclass(frozen=True)
class NotifyDecision:
    should_notify: bool
    flags: tuple[str, ...]
    reason: str


def notify_decision(
    record: TriageRecord,
    session: SessionState,
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
    *,
    event_timestamp: datetime,
    max_event_age_s: float = _DEFAULT_MAX_EVENT_AGE_S,
    now: datetime | None = None,
) -> NotifyDecision:
    """Evaluate the 5-level notification decision tree.

    Returns NotifyDecision — never raises, never sends.
    Flags are passed to the template renderer; reason is for logging/metrics.

    Decision levels (evaluated in order):
      0. Event age cutoff (ADR-0004 Enmienda 2026-08, D-16/D-20) — the sole documented
         exception to "every critical always notifies". Suppression here is loud (a
         coalesced system notification), never silent, and nothing upstream of notify is
         skipped: the event was still ingested, classified, grouped and persisted.
      1. Severity floor  (high/critical → always a candidate)
      2. Confidence gate (confidence < threshold → candidate via doubt)
      3. Model judgment  (classification == alert → candidate)
      --- if not a candidate: suppress ---
      4. Session granularity (new session / not yet notified / already notified)

    event_timestamp is required: level 0 is a fail-loud safety guardrail (ADR-0004/
    ADR-0005) and must never silently no-op because a caller forgot to pass it. Callers
    that don't have a real wall-clock reading for "now" may omit it; it then defaults to
    the current time via datetime.now(UTC).
    """
    current = now if now is not None else datetime.now(UTC)
    age_s = (current - event_timestamp).total_seconds()
    if age_s > max_event_age_s:
        return NotifyDecision(should_notify=False, flags=(), reason="age_suppressed")

    flags: list[str] = []
    is_candidate = False

    if record.severity in _SEVERITY_FLOOR:
        is_candidate = True
        flags.append("severity_floor")
        if record.classification == Classification.NOISE:
            flags.append("false_positive_candidate")

    elif record.confidence < confidence_threshold:
        is_candidate = True
        flags.append("low_confidence")

    elif record.classification == Classification.ALERT:
        is_candidate = True

    if not is_candidate:
        return NotifyDecision(
            should_notify=False,
            flags=tuple(flags),
            reason="not_candidate",
        )

    # Level 4: session granularity
    if session.is_new_session:
        return NotifyDecision(
            should_notify=True,
            flags=tuple(flags),
            reason="new_session",
        )

    if not session.session_was_notified:
        return NotifyDecision(
            should_notify=True,
            flags=tuple(flags),
            reason="intra_session_escalation",
        )

    return NotifyDecision(
        should_notify=False,
        flags=tuple(flags),
        reason="suppressed",
    )
