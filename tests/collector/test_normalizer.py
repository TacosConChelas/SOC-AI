"""Tests for the Wazuh alert normalizer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.collector.normalizer import _severity_from_level, normalize


def _hids_alert(**overrides: object) -> dict:
    base: dict = {
        "id": "1234567890.123456",
        "timestamp": "2026-07-20T12:00:00.000+0000",
        "rule": {
            "id": "5710",
            "description": "PAM: Multiple failed logins in a small period of time.",
            "level": 10,
            "groups": ["authentication", "sshd", "authentication_failures"],
            "mitre": {"id": ["T1110.001"]},
        },
        "agent": {"id": "001", "name": "victim-host"},
        "data": {"srcip": "203.0.113.5", "dstip": None},
    }
    base.update(overrides)
    return base


def _suricata_alert(**overrides: object) -> dict:
    base: dict = {
        "id": "9876543210.654321",
        "timestamp": "2026-07-20T12:01:00.000+0000",
        "rule": {
            "id": "86601",
            "description": "Suricata: ET SCAN Nmap NSE",
            "level": 6,
            "groups": ["ids", "suricata"],
        },
        "agent": {"id": "002", "name": "edge-01"},
        "data": {
            "srcip": "203.0.113.5",
            "srcport": "54321",
            "dstip": "10.0.0.1",
            "dstport": "22",
            "protocol": "TCP",
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        # ADR-0001 Wazuh bands: low 1–4, medium 5–9, high 10–13, critical 14–15.
        # Level 0 maps defensively to low (decisions.md:104).
        (0, "low"),
        (1, "low"),
        (4, "low"),
        (5, "medium"),
        (9, "medium"),
        (10, "high"),
        (13, "high"),
        (14, "critical"),
        (15, "critical"),
    ],
)
def test_severity_from_level(level: int, expected: str) -> None:
    assert _severity_from_level(level) == expected


# ---------------------------------------------------------------------------
# HIDS alert normalization
# ---------------------------------------------------------------------------


def test_hids_alert_basic_fields() -> None:
    event = normalize(_hids_alert())
    assert event.event_id == "1234567890.123456"
    assert event.source_module == "wazuh"
    assert event.sensor == "victim-host"
    assert event.source_alert_id == "1234567890.123456"
    assert event.event_type == "HIDS"
    assert event.severity_hint == "high"  # level 10
    assert event.rule_id == "5710"
    assert event.mitre_technique_ids == ["T1110.001"]


def test_hids_alert_timestamp_is_utc_aware() -> None:
    event = normalize(_hids_alert())
    assert event.timestamp.tzinfo is not None
    assert event.timestamp == datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


def test_hids_alert_src_ip_parsed() -> None:
    event = normalize(_hids_alert())
    assert str(event.src_ip) == "203.0.113.5"


def test_hids_alert_raw_ref_format() -> None:
    event = normalize(_hids_alert())
    assert event.raw_ref == "opensearch://wazuh-alerts-*/1234567890.123456"


# ---------------------------------------------------------------------------
# Suricata alert normalization
# ---------------------------------------------------------------------------


def test_suricata_alert_event_type_is_nids() -> None:
    event = normalize(_suricata_alert())
    assert event.event_type == "NIDS"


def test_suricata_alert_ports_parsed() -> None:
    event = normalize(_suricata_alert())
    assert event.src_port == 54321
    assert event.dst_port == 22


def test_suricata_alert_no_mitre_ids() -> None:
    """Suricata alerts (rule 86601) carry no mitre block → mitre_technique_ids is None."""
    event = normalize(_suricata_alert())
    assert event.mitre_technique_ids is None


def test_suricata_alert_protocol() -> None:
    event = normalize(_suricata_alert())
    assert event.protocol == "TCP"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_unknown_src_ip_becomes_none() -> None:
    alert = _hids_alert()
    alert["data"] = {"srcip": "Unknown"}
    event = normalize(alert)
    assert event.src_ip is None


def test_empty_src_ip_becomes_none() -> None:
    alert = _hids_alert()
    alert["data"] = {}
    event = normalize(alert)
    assert event.src_ip is None


def test_invalid_port_becomes_none() -> None:
    alert = _suricata_alert()
    alert["data"] = {**alert["data"], "srcport": "not-a-port"}
    event = normalize(alert)
    assert event.src_port is None


def test_port_out_of_range_becomes_none() -> None:
    alert = _suricata_alert()
    alert["data"] = {**alert["data"], "dstport": "99999"}
    event = normalize(alert)
    assert event.dst_port is None


def test_fim_event_type() -> None:
    alert = _hids_alert()
    alert["rule"]["groups"] = ["syscheck", "fim"]
    event = normalize(alert)
    assert event.event_type == "FIM"


def test_unknown_group_falls_back_to_siem() -> None:
    alert = _hids_alert()
    alert["rule"]["groups"] = ["custom_decoder"]
    event = normalize(alert)
    assert event.event_type == "SIEM"


def test_summary_truncated_to_500_chars() -> None:
    alert = _hids_alert()
    alert["rule"]["description"] = "X" * 600
    event = normalize(alert)
    assert len(event.summary) == 500


def test_missing_required_field_raises() -> None:
    with pytest.raises((ValueError, KeyError, TypeError)):
        normalize({})
