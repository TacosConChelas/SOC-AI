"""Tests for triage contracts — step 1.4."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.contracts.triage import (
    Classification,
    Severity,
    TriageContext,
    TriageModelOutput,
    TriageRecord,
)


VALID_MODEL_OUTPUT = {
    "classification": "alert",
    "confidence": 0.91,
    "summary": "Nmap NSE scan detected",
    "suggested_actions": ["Block 203.0.113.5 at firewall"],
    "rationale": "Repeated scanner activity from a single external IP.",
}

VALID_CONTEXT = {
    "src_ip_seen_before": True,
    "related_events_24h": 47,
    "distinct_rules_from_src_24h": 1,
    "events_last_10min": 5,
    "src_in_allowlist": False,
    "matched_rule": "2024358",
}


def test_model_output_valid_json():
    out = TriageModelOutput.model_validate_json(json.dumps(VALID_MODEL_OUTPUT))
    assert out.classification == Classification.ALERT
    assert out.confidence == 0.91


def test_model_output_rejects_extra_field():
    bad = {**VALID_MODEL_OUTPUT, "alert_id": "should-not-be-here"}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_model_output_rejects_confidence_below_zero():
    bad = {**VALID_MODEL_OUTPUT, "confidence": -0.1}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_model_output_rejects_confidence_above_one():
    bad = {**VALID_MODEL_OUTPUT, "confidence": 1.01}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_model_output_rejects_too_many_actions():
    bad = {**VALID_MODEL_OUTPUT, "suggested_actions": [f"action {i}" for i in range(11)]}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_model_output_rejects_action_too_long():
    bad = {**VALID_MODEL_OUTPUT, "suggested_actions": ["x" * 201]}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_model_output_rejects_markdown_fenced_json():
    fenced = "```json\n" + json.dumps(VALID_MODEL_OUTPUT) + "\n```"
    with pytest.raises((ValidationError, Exception)):
        TriageModelOutput.model_validate_json(fenced)


def test_model_output_rejects_unknown_classification():
    bad = {**VALID_MODEL_OUTPUT, "classification": "suspicious"}
    with pytest.raises(ValidationError):
        TriageModelOutput.model_validate_json(json.dumps(bad))


def test_context_is_frozen():
    ctx = TriageContext(**VALID_CONTEXT)
    with pytest.raises(Exception):
        ctx.matched_rule = "changed"  # type: ignore[misc]


def test_context_lookup_degraded_defaults_false():
    ctx = TriageContext(**VALID_CONTEXT)
    assert ctx.lookup_degraded is False


def test_triage_record_assembles_all_fields():
    model_out = TriageModelOutput.model_validate_json(json.dumps(VALID_MODEL_OUTPUT))
    ctx = TriageContext(**VALID_CONTEXT)
    record = TriageRecord(
        alert_id="alert-001",
        event_id="evt-001",
        classification=model_out.classification,
        confidence=model_out.confidence,
        severity=Severity.MEDIUM,
        summary=model_out.summary,
        incident_group_key="group-001",
        context=ctx,
        suggested_actions=model_out.suggested_actions,
        rationale=model_out.rationale,
        triaged_at=datetime.now(UTC),
    )
    assert record.severity == Severity.MEDIUM
    assert record.context.related_events_24h == 47


def test_severity_enum_values():
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"


def test_classification_enum_values():
    assert Classification.NOISE == "noise"
    assert Classification.INFORMATIONAL == "informational"
    assert Classification.ALERT == "alert"
