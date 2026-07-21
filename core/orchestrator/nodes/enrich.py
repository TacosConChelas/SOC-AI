"""Enrich node — OpenSearch context lookup before classification."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

from core.contracts.event import UnifiedEvent, matched_rule_of
from core.contracts.triage import TriageContext
from core.observability.metrics import ENRICHMENT_FAILURES

_THIRTY_DAYS_S = 30 * 24 * 3600
_TWENTY_FOUR_H_S = 24 * 3600
_TEN_MIN_S = 600


def _allowlist() -> frozenset[str]:
    raw = os.getenv("SOC_SOURCE_ALLOWLIST", "")
    return frozenset(s.strip() for s in raw.split(",") if s.strip())


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _zeroed(event: UnifiedEvent) -> TriageContext:
    return TriageContext(
        src_ip_seen_before=False,
        related_events_24h=0,
        distinct_rules_from_src_24h=0,
        events_last_10min=0,
        src_in_allowlist=False,
        matched_rule=matched_rule_of(event),
        lookup_degraded=True,
    )


def enrich_event(event: UnifiedEvent, os_client: Any) -> TriageContext:  # noqa: C901
    """Run 4 OpenSearch lookups and return TriageContext.

    All range queries use `lt=event.timestamp` (exclusive) so the current
    alert is never counted in its own prior-history metrics.
    On any OS failure: return zeroed context with lookup_degraded=True,
    never raise.
    """
    ts_lt = _iso(event.timestamp)
    src = str(event.src_ip) if event.src_ip is not None else None
    sensor = event.sensor
    rule = matched_rule_of(event)
    is_host_event = src is None

    # aggregation key mirrors ADR-0002 session signature
    agg_key = sensor if is_host_event else src

    try:
        # 1. src_ip_seen_before — exists query, 30d, lt exclusive
        if is_host_event:
            seen_before = False
        else:
            ts_30d_ago = _iso(event.timestamp.astimezone(UTC).replace(tzinfo=UTC) - timedelta(seconds=_THIRTY_DAYS_S))
            resp = os_client.search(
                index="wazuh-alerts-*",
                body={
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"data.srcip": src}},
                                {"range": {"@timestamp": {"gte": ts_30d_ago, "lt": ts_lt}}},
                            ]
                        }
                    },
                    "aggs": {"exists_check": {"value_count": {"field": "_id"}}},
                },
            )
            seen_before = resp["hits"]["total"]["value"] > 0

        # 2. related_events_24h — count, same rule + agg_key, 24h, lt exclusive
        ts_24h_ago = _iso(event.timestamp.astimezone(UTC) - timedelta(seconds=_TWENTY_FOUR_H_S))
        field_24h = "agent.name" if is_host_event else "data.srcip"
        resp_24h = os_client.search(
            index="wazuh-alerts-*",
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {field_24h: agg_key}},
                            {"term": {"rule.id": rule}},
                            {"range": {"@timestamp": {"gte": ts_24h_ago, "lt": ts_lt}}},
                        ]
                    }
                },
                "aggs": {"events_24h": {"value_count": {"field": "_id"}}},
            },
        )
        count_24h = resp_24h["hits"]["total"]["value"]

        # 3. events_last_10min — count, same agg_key, 10min, lt exclusive
        ts_10min_ago = _iso(event.timestamp.astimezone(UTC) - timedelta(seconds=_TEN_MIN_S))
        resp_10min = os_client.search(
            index="wazuh-alerts-*",
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {field_24h: agg_key}},
                            {"range": {"@timestamp": {"gte": ts_10min_ago, "lt": ts_lt}}},
                        ]
                    }
                },
                "aggs": {"events_10min": {"value_count": {"field": "_id"}}},
            },
        )
        count_10min = resp_10min["hits"]["total"]["value"]

        # 4. distinct_rules_from_src_24h — cardinality, same agg_key, 24h, lt exclusive
        resp_card = os_client.search(
            index="wazuh-alerts-*",
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {field_24h: agg_key}},
                            {"range": {"@timestamp": {"gte": ts_24h_ago, "lt": ts_lt}}},
                        ]
                    }
                },
                "aggs": {"distinct_rules": {"cardinality": {"field": "rule.id"}}},
            },
        )
        cardinality = resp_card["aggregations"]["distinct_rules"]["value"]

        allowlist = _allowlist()
        in_allowlist = (agg_key in allowlist) if agg_key else False

        return TriageContext(
            src_ip_seen_before=seen_before,
            related_events_24h=count_24h,
            distinct_rules_from_src_24h=cardinality,
            events_last_10min=count_10min,
            src_in_allowlist=in_allowlist,
            matched_rule=rule,
            lookup_degraded=False,
        )

    except Exception:
        ENRICHMENT_FAILURES.inc()
        return _zeroed(event)
