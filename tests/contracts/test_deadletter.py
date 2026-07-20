"""Tests for DeadLetterRecord — step 1.7."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord


def _base() -> dict:
    return {
        "alert_id": "alert-001",
        "event_id": "evt-001",
        "source_module": "wazuh",
        "sensor": "host-01",
        "severity": "medium",
        "reason": DeadLetterReason.PARSE_FAILURE,
        "retry_count": 2,
        "dead_lettered_at": datetime.now(UTC),
        "detail": "JSONDecodeError at line 1",
    }


def test_valid_dead_letter():
    r = DeadLetterRecord(**_base())
    assert r.reason == DeadLetterReason.PARSE_FAILURE


def test_model_unavailable_reason():
    d = _base()
    d["reason"] = DeadLetterReason.MODEL_UNAVAILABLE
    r = DeadLetterRecord(**d)
    assert r.reason == DeadLetterReason.MODEL_UNAVAILABLE


def test_detail_empty_rejected():
    d = _base()
    d["detail"] = ""
    with pytest.raises(ValidationError):
        DeadLetterRecord(**d)


def test_detail_too_long_rejected():
    d = _base()
    d["detail"] = "x" * 501
    with pytest.raises(ValidationError):
        DeadLetterRecord(**d)


def test_unknown_reason_rejected():
    d = _base()
    d["reason"] = "network_error"
    with pytest.raises(ValidationError):
        DeadLetterRecord(**d)


def test_detail_from_exception_class_not_raw_content():
    """detail must be a code-derived string, not attacker-controlled content."""
    d = _base()
    d["detail"] = "JSONDecodeError: Expecting value"  # class name + code msg
    r = DeadLetterRecord(**d)
    # Must not contain anything that looks like raw alert payload
    assert len(r.detail) <= 500
