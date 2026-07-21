"""Notify node — 4-level decision tree (ADR-0004, flow doc §3)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from core.contracts.triage import Classification, Severity, TriageRecord
from core.orchestrator.nodes.group import SessionState

_SEVERITY_FLOOR = frozenset({Severity.HIGH, Severity.CRITICAL})

_DEFAULT_CONFIDENCE_THRESHOLD = float(os.getenv("SOC_CONFIDENCE_THRESHOLD", "0.7"))


@dataclass(frozen=True)
class NotifyDecision:
    should_notify: bool
    flags: tuple[str, ...]
    reason: str


def notify_decision(
    record: TriageRecord,
    session: SessionState,
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
) -> NotifyDecision:
    """Evaluate the 4-level notification decision tree.

    Returns NotifyDecision — never raises, never sends.
    Flags are passed to the template renderer; reason is for logging/metrics.

    Decision levels (evaluated in order):
      1. Severity floor  (high/critical → always a candidate)
      2. Confidence gate (confidence < threshold → candidate via doubt)
      3. Model judgment  (classification == alert → candidate)
      --- if not a candidate: suppress ---
      4. Session granularity (new session / not yet notified / already notified)
    """
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
