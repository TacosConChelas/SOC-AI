"""Tests for training/pipeline/normalize.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from training.pipeline.normalize import (
    from_csv,
    from_jsonl,
    from_kaggle_row,
    normalize_raw,
)


def _base_row() -> dict:
    return {
        "event_id": "test-001",
        "timestamp": "2026-07-21T12:00:00+00:00",
        "source_module": "wazuh",
        "sensor": "host-01",
        "source_alert_id": "wz-001",
        "event_type": "NIDS",
        "severity_hint": "medium",
        "summary": "Port scan detected",
        "raw_ref": "opensearch://wazuh-alerts/test-001",
        "src_ip": "203.0.113.5",
        "signature": "ET SCAN Nmap",
    }


def test_normalize_raw_minimal() -> None:
    row = _base_row()
    event, ctx = normalize_raw(row)
    assert event.event_id == "test-001"
    assert event.schema_version == "unified-event@1"
    assert event.timestamp == datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    assert str(event.src_ip) == "203.0.113.5"
    assert event.signature == "ET SCAN Nmap"


def test_normalize_raw_no_context_yields_degraded() -> None:
    row = _base_row()
    _, ctx = normalize_raw(row)
    assert ctx.lookup_degraded is True
    assert ctx.related_events_24h == 0
    assert ctx.src_ip_seen_before is False


def test_normalize_raw_with_context() -> None:
    row = {
        **_base_row(),
        "ctx_src_ip_seen_before": True,
        "ctx_related_events_24h": 47,
        "ctx_distinct_rules_from_src_24h": 3,
        "ctx_events_last_10min": 12,
        "ctx_src_in_allowlist": False,
        "ctx_matched_rule": "2024358",
        "ctx_lookup_degraded": False,
    }
    _, ctx = normalize_raw(row)
    assert ctx.lookup_degraded is False
    assert ctx.related_events_24h == 47
    assert ctx.distinct_rules_from_src_24h == 3
    assert ctx.matched_rule == "2024358"


def test_normalize_raw_fallback_timestamp() -> None:
    """Missing timestamp defaults to now (timezone-aware)."""
    row = {**_base_row()}
    del row["timestamp"]
    event, _ = normalize_raw(row)
    assert event.timestamp.tzinfo is not None


def test_normalize_raw_summary_truncated_at_500() -> None:
    row = {**_base_row(), "summary": "A" * 600}
    event, _ = normalize_raw(row)
    assert len(event.summary) == 500


def test_from_kaggle_row_maps_columns() -> None:
    kaggle_row = {
        "EventID": "k-001",
        "Timestamp": "2026-07-21T10:00:00Z",
        "SourceIP": "10.0.0.1",
        "DestinationIP": "10.0.0.2",
        "SourcePort": "4444",
        "DestinationPort": "80",
        "Protocol": "TCP",
        "AlertType": "Port Scan",
        "Severity": "Medium",
        "Description": "Nmap scan",
        "Label": "false positive",
    }
    intermediate = from_kaggle_row(kaggle_row)
    assert intermediate["severity_hint"] == "medium"
    assert intermediate["native_label"] == "false positive"
    assert intermediate["src_ip"] == "10.0.0.1"


def test_from_csv(tmp_path: object) -> None:
    import csv as _csv

    path = str(tmp_path) + "/test.csv"  # type: ignore[operator]
    fieldnames = ["EventID", "Timestamp", "SourceIP", "DestinationIP", "SourcePort",
                  "DestinationPort", "Protocol", "AlertType", "Severity", "Description", "Label"]
    with open(path, "w", newline="") as f:
        writer = _csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({
            "EventID": "csv-001",
            "Timestamp": "2026-07-21T00:00:00+00:00",
            "SourceIP": "1.2.3.4",
            "DestinationIP": "5.6.7.8",
            "SourcePort": "1234",
            "DestinationPort": "80",
            "Protocol": "TCP",
            "AlertType": "NIDS",
            "Severity": "high",
            "Description": "Test alert",
            "Label": "true positive",
        })

    results = list(from_csv(path, source="kaggle"))
    assert len(results) == 1
    event, ctx, native_label = results[0]
    assert event.event_id == "csv-001"
    assert native_label == "true positive"
    assert ctx.lookup_degraded is True  # no ctx_* keys in Kaggle rows


def test_from_jsonl(tmp_path: object) -> None:
    path = str(tmp_path) + "/manual.jsonl"  # type: ignore[operator]
    row = {
        **_base_row(),
        "ctx_related_events_24h": 5,
        "ctx_lookup_degraded": False,
        "ctx_matched_rule": "550",
        "native_label": "informational",
    }
    with open(path, "w") as f:
        f.write(json.dumps(row) + "\n")

    results = list(from_jsonl(path))
    assert len(results) == 1
    event, ctx, label = results[0]
    assert event.event_id == "test-001"
    assert ctx.related_events_24h == 5
    assert label == "informational"
