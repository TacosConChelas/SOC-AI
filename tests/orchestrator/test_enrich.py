"""Tests for the enrich node — OpenSearch context lookup."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

import pytest

from core.contracts.event import UnifiedEvent
from core.contracts.triage import TriageContext
from core.orchestrator.nodes.enrich import enrich_event


def _event(
    *,
    src_ip: str | None = "203.0.113.5",
    rule_id: str | None = "1002",
    sensor: str = "host-01",
    ts: datetime | None = None,
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-001",
        schema_version="unified-event@1",
        timestamp=ts or datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor=sensor,
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="medium",
        summary="Test alert",
        raw_ref="opensearch://soc-alerts/wz-1",
        src_ip=src_ip,
        rule_id=rule_id,
    )


def _os_client(
    *,
    exists: bool = True,
    count_24h: int = 5,
    count_10min: int = 2,
    cardinality: int = 3,
) -> MagicMock:
    """Fake OpenSearch client returning controlled aggregation results."""
    client = MagicMock()

    def search_side_effect(**kwargs: object) -> dict:
        body = kwargs.get("body", {})
        aggs = body.get("aggs", {}) if isinstance(body, dict) else {}
        if "exists_check" in aggs:
            return {"hits": {"total": {"value": 1 if exists else 0}}}
        if "events_24h" in aggs:
            return {"hits": {"total": {"value": count_24h}}}
        if "events_10min" in aggs:
            return {"hits": {"total": {"value": count_10min}}}
        if "distinct_rules" in aggs:
            return {
                "aggregations": {"distinct_rules": {"value": cardinality}},
                "hits": {"total": {"value": 10}},
            }
        return {"hits": {"total": {"value": 0}}}

    client.search.side_effect = search_side_effect
    return client


# ---------------------------------------------------------------------------
# Network events (with src_ip)
# ---------------------------------------------------------------------------


def test_enrich_network_event_returns_context() -> None:
    ctx = enrich_event(_event(), _os_client(exists=True, count_24h=47, count_10min=12, cardinality=3))
    assert isinstance(ctx, TriageContext)
    assert ctx.src_ip_seen_before is True
    assert ctx.related_events_24h == 47
    assert ctx.events_last_10min == 12
    assert ctx.distinct_rules_from_src_24h == 3
    assert ctx.lookup_degraded is False


def test_enrich_uses_event_timestamp_lt_exclusive() -> None:
    """Lookups must use lt=event.timestamp so the current event is excluded."""
    client = _os_client()
    ts = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    enrich_event(_event(ts=ts), client)
    for call in client.search.call_args_list:
        body = call.kwargs.get("body", call.args[0] if call.args else {})
        query_str = str(body)
        assert "lt" in query_str, "All range queries must be exclusive (lt)"


def test_enrich_src_ip_not_seen_before() -> None:
    ctx = enrich_event(_event(), _os_client(exists=False))
    assert ctx.src_ip_seen_before is False


def test_enrich_src_in_allowlist_from_env() -> None:
    with patch.dict("os.environ", {"SOC_SOURCE_ALLOWLIST": "203.0.113.5,10.0.0.1"}):
        ctx = enrich_event(_event(src_ip="203.0.113.5"), _os_client())
    assert ctx.src_in_allowlist is True


def test_enrich_src_not_in_allowlist() -> None:
    with patch.dict("os.environ", {"SOC_SOURCE_ALLOWLIST": "10.0.0.1"}):
        ctx = enrich_event(_event(src_ip="203.0.113.5"), _os_client())
    assert ctx.src_in_allowlist is False


def test_enrich_matched_rule_from_event() -> None:
    ctx = enrich_event(_event(rule_id="5502"), _os_client())
    assert ctx.matched_rule == "5502"


# ---------------------------------------------------------------------------
# Host events (no src_ip) — fallback to sensor
# ---------------------------------------------------------------------------


def test_enrich_host_event_src_ip_seen_before_always_false() -> None:
    """Host events always have src_ip_seen_before=False regardless of OS response."""
    ctx = enrich_event(_event(src_ip=None), _os_client(exists=True))
    assert ctx.src_ip_seen_before is False


def test_enrich_host_event_uses_sensor_as_key() -> None:
    client = _os_client(count_24h=3)
    enrich_event(_event(src_ip=None, sensor="fim-host-01"), client)
    query_str = str(client.search.call_args_list)
    assert "fim-host-01" in query_str


# ---------------------------------------------------------------------------
# Degraded path — OpenSearch down
# ---------------------------------------------------------------------------


def test_enrich_os_down_returns_zeroed_context() -> None:
    bad_client = MagicMock()
    bad_client.search.side_effect = Exception("Connection refused")
    ctx = enrich_event(_event(), bad_client)
    assert ctx.lookup_degraded is True
    assert ctx.src_ip_seen_before is False
    assert ctx.related_events_24h == 0
    assert ctx.events_last_10min == 0
    assert ctx.distinct_rules_from_src_24h == 0
    assert ctx.src_in_allowlist is False


def test_enrich_os_down_never_raises() -> None:
    bad_client = MagicMock()
    bad_client.search.side_effect = RuntimeError("timeout")
    result = enrich_event(_event(), bad_client)
    assert isinstance(result, TriageContext)


def test_enrich_os_down_increments_metric() -> None:
    from core.orchestrator.nodes.enrich import ENRICHMENT_FAILURES

    bad_client = MagicMock()
    bad_client.search.side_effect = Exception("OS down")
    before = ENRICHMENT_FAILURES._value.get()  # type: ignore[attr-defined]
    enrich_event(_event(), bad_client)
    after = ENRICHMENT_FAILURES._value.get()  # type: ignore[attr-defined]
    assert after == before + 1
