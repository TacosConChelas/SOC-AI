"""Tests for UnifiedEvent contract — step 1.1."""

from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError

from core.contracts.event import UnifiedEvent, matched_rule_of


def _base() -> dict:
    return {
        "event_id": "evt-001",
        "schema_version": "unified-event@1",
        "timestamp": datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc),
        "source_module": "wazuh",
        "sensor": "host-01",
        "source_alert_id": "alert-001",
        "event_type": "network_connection",
        "severity_hint": "medium",
        "summary": "Outbound connection to suspicious IP",
        "raw_ref": "os://wazuh-alerts/alert-001",
        "src_ip": "10.0.0.1",
        "dst_ip": "203.0.113.5",
        "src_port": 54321,
        "dst_port": 443,
    }


def test_valid_network_event():
    e = UnifiedEvent(**_base())
    assert str(e.src_ip) == "10.0.0.1"
    assert e.timestamp.tzinfo is not None


def test_naive_timestamp_rejected():
    d = _base()
    d["timestamp"] = datetime(2026, 7, 20, 12, 0, 0)  # naive
    with pytest.raises(ValidationError, match="timezone"):
        UnifiedEvent(**d)


def test_extra_field_rejected():
    d = _base()
    d["unexpected_field"] = "boom"
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_host_event_without_src_ip_is_valid():
    d = _base()
    d["event_type"] = "fim"
    del d["src_ip"]
    del d["dst_ip"]
    del d["src_port"]
    del d["dst_port"]
    e = UnifiedEvent(**d)
    assert e.src_ip is None


def test_invalid_ip_rejected():
    d = _base()
    d["src_ip"] = "999.999.999.999"
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_port_out_of_range_rejected():
    d = _base()
    d["dst_port"] = 65536
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_summary_too_long_rejected():
    d = _base()
    d["summary"] = "x" * 501
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_summary_empty_rejected():
    d = _base()
    d["summary"] = ""
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_fields_over_4096_bytes_rejected():
    d = _base()
    d["fields"] = {"k": "v" * 4100}
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_wrong_schema_version_rejected():
    d = _base()
    d["schema_version"] = "v2"
    with pytest.raises(ValidationError):
        UnifiedEvent(**d)


def test_timestamp_normalized_to_utc():
    d = _base()
    plus2 = timezone(timedelta(hours=2))
    d["timestamp"] = datetime(2026, 7, 20, 14, 0, 0, tzinfo=plus2)
    e = UnifiedEvent(**d)
    assert e.timestamp.tzinfo == timezone.utc
    assert e.timestamp.hour == 12


def test_matched_rule_of_prefers_rule_id():
    d = _base()
    d["rule_id"] = "550"
    d["signature"] = "ET SCAN"
    e = UnifiedEvent(**d)
    assert matched_rule_of(e) == "550"


def test_matched_rule_of_falls_back_to_signature():
    d = _base()
    d["signature"] = "ET SCAN"
    e = UnifiedEvent(**d)
    assert matched_rule_of(e) == "ET SCAN"


def test_matched_rule_of_falls_back_to_event_type():
    e = UnifiedEvent(**_base())
    assert matched_rule_of(e) == "network_connection"
