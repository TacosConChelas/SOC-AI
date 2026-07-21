"""Tests for the classify node — Ollama client + retry logic."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from core.contracts.deadletter import DeadLetterReason
from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, TriageContext, TriageModelOutput
from core.orchestrator.nodes.classify import (
    ClassifyOutcome,
    OllamaClient,
    OllamaUnavailableError,
    classify_event,
)

_VALID_JSON = """{
  "classification": "alert",
  "confidence": 0.91,
  "summary": "Nmap scan from 203.0.113.5",
  "suggested_actions": ["Block at firewall"],
  "rationale": "High-volume scanner with prior history."
}"""

_INVALID_JSON = '{"classification": "unknown", "confidence": 2.0}'

_FENCED_JSON = "```json\n" + _VALID_JSON + "\n```"


def _event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-001",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="host-01",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="medium",
        summary="Scan detected",
        raw_ref="opensearch://soc-alerts/wz-1",
    )


def _context() -> TriageContext:
    return TriageContext(
        src_ip_seen_before=True,
        related_events_24h=47,
        distinct_rules_from_src_24h=3,
        events_last_10min=12,
        src_in_allowlist=False,
        matched_rule="2024358",
    )


def _fake_ollama(response: str, raises: Exception | None = None) -> OllamaClient:
    client = MagicMock(spec=OllamaClient)
    if raises is not None:
        client.chat.side_effect = raises
    else:
        client.chat.return_value = response
    return client


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_classify_valid_json_returns_model_output() -> None:
    outcome = classify_event(_event(), _context(), _fake_ollama(_VALID_JSON))
    assert outcome.model_output is not None
    assert isinstance(outcome.model_output, TriageModelOutput)
    assert outcome.model_output.classification == Classification.ALERT
    assert outcome.model_output.confidence == pytest.approx(0.91)
    assert outcome.dead_letter is None


# ---------------------------------------------------------------------------
# Parse failure — 2 retries, no feedback
# ---------------------------------------------------------------------------


def test_classify_invalid_json_after_retries_produces_dead_letter() -> None:
    client = _fake_ollama(_INVALID_JSON)
    outcome = classify_event(_event(), _context(), client)
    assert outcome.model_output is None
    assert outcome.dead_letter is not None
    assert outcome.dead_letter.reason == DeadLetterReason.PARSE_FAILURE
    assert outcome.dead_letter.retry_count == 2


def test_classify_retries_exactly_twice_on_parse_failure() -> None:
    client = _fake_ollama(_INVALID_JSON)
    classify_event(_event(), _context(), client)
    assert client.chat.call_count == 2


def test_classify_no_feedback_between_retries() -> None:
    """The same prompt is sent on every retry — no error fed back to the model."""
    client = _fake_ollama(_INVALID_JSON)
    classify_event(_event(), _context(), client)
    calls = client.chat.call_args_list
    assert len(calls) == 2
    assert calls[0] == calls[1], "Retry must send identical prompt, no error feedback"


def test_classify_fenced_json_treated_as_parse_failure() -> None:
    """```json fences are a format failure per hard rule 4."""
    outcome = classify_event(_event(), _context(), _fake_ollama(_FENCED_JSON))
    assert outcome.dead_letter is not None
    assert outcome.dead_letter.reason == DeadLetterReason.PARSE_FAILURE


def test_classify_parse_failure_does_not_raise() -> None:
    outcome = classify_event(_event(), _context(), _fake_ollama(_INVALID_JSON))
    assert isinstance(outcome, ClassifyOutcome)


def test_classify_parse_failure_dead_letter_detail_no_verbatim() -> None:
    """detail must contain error type names, never the raw model output."""
    outcome = classify_event(_event(), _context(), _fake_ollama(_INVALID_JSON))
    assert outcome.dead_letter is not None
    assert _INVALID_JSON not in outcome.dead_letter.detail


# ---------------------------------------------------------------------------
# Ollama unavailable
# ---------------------------------------------------------------------------


def test_classify_ollama_unavailable_produces_dead_letter() -> None:
    client = _fake_ollama("", raises=OllamaUnavailableError("connection refused"))
    outcome = classify_event(_event(), _context(), client)
    assert outcome.model_output is None
    assert outcome.dead_letter is not None
    assert outcome.dead_letter.reason == DeadLetterReason.MODEL_UNAVAILABLE


def test_classify_ollama_unavailable_does_not_raise() -> None:
    client = _fake_ollama("", raises=OllamaUnavailableError("timeout"))
    outcome = classify_event(_event(), _context(), client)
    assert isinstance(outcome, ClassifyOutcome)


def test_classify_succeeds_on_second_attempt() -> None:
    client = MagicMock(spec=OllamaClient)
    client.chat.side_effect = [_INVALID_JSON, _VALID_JSON]
    outcome = classify_event(_event(), _context(), client)
    assert outcome.model_output is not None
    assert outcome.dead_letter is None
    assert client.chat.call_count == 2
