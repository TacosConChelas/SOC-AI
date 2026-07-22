"""Centralized soc_* prometheus metrics — allowlist-gated to prevent label leakage.

Privacy rule 6 / ADR-0005 §2: labels must be closed enums, never alert content.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram
from prometheus_client import start_http_server as _start

# Closed allowlist: name → permitted label names.
# The contract test fails if any metric's labels diverge from this table.
_LABEL_ALLOWLIST: dict[str, frozenset[str]] = {
    "soc_enrichment_failures_total": frozenset(),
    "soc_deadletter_total": frozenset({"reason"}),
    "soc_events_processed_total": frozenset({"outcome"}),
    "soc_triage_duration_seconds": frozenset(),
    "soc_collector_published_total": frozenset(),
    "soc_collector_quarantined_total": frozenset(),
    "soc_classify_total": frozenset({"outcome"}),
    "soc_notify_total": frozenset({"decision"}),
    "soc_group_total": frozenset({"action"}),
    "soc_bus_acl_rejections_total": frozenset(),
    "soc_bus_xadd_duration_seconds": frozenset(),
    "soc_bus_xreadgroup_duration_seconds": frozenset(),
}

ENRICHMENT_FAILURES: Counter = Counter(
    "soc_enrichment_failures_total",
    "OpenSearch lookups that failed (degraded context emitted)",
)
DEADLETTER_TOTAL: Counter = Counter(
    "soc_deadletter_total",
    "Events dead-lettered by reason",
    ["reason"],
)
EVENTS_PROCESSED: Counter = Counter(
    "soc_events_processed_total",
    "Events consumed and processed by the triage graph",
    ["outcome"],
)
TRIAGE_DURATION: Histogram = Histogram(
    "soc_triage_duration_seconds",
    "End-to-end latency of one triage cycle (target ≤ 3 s median)",
    buckets=[0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 30.0],
)
COLLECTOR_PUBLISHED: Counter = Counter(
    "soc_collector_published_total",
    "Alerts published to the event bus",
)
COLLECTOR_QUARANTINED: Counter = Counter(
    "soc_collector_quarantined_total",
    "Alerts rejected at the normalization boundary (quarantined)",
)
CLASSIFY_TOTAL: Counter = Counter(
    "soc_classify_total",
    "Classify node outcomes",
    ["outcome"],  # "success" | "parse_failure" | "model_unavailable"
)
NOTIFY_TOTAL: Counter = Counter(
    "soc_notify_total",
    "Notify node decisions",
    ["decision"],  # "notified" | "suppressed"
)
GROUP_TOTAL: Counter = Counter(
    "soc_group_total",
    "Group node session actions",
    ["action"],  # "new_session" | "folded"
)

# Bus KPI metrics — Familia 5 (security) + Familia 8 (bus latency)
BUS_ACL_REJECTIONS: Counter = Counter(
    "soc_bus_acl_rejections_total",
    "Redis commands rejected by ACL (NOPERM / NOAUTH)",
)
BUS_XADD_DURATION: Histogram = Histogram(
    "soc_bus_xadd_duration_seconds",
    "Latency of XADD publish calls",
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)
BUS_XREADGROUP_DURATION: Histogram = Histogram(
    "soc_bus_xreadgroup_duration_seconds",
    "Latency of XREADGROUP consume calls (includes block time when idle)",
    buckets=[0.1, 1.0, 5.0, 10.0, 20.0, 30.0],
)


def start_http_server(port: int) -> None:
    """Start prometheus /metrics HTTP endpoint in a daemon thread."""
    _start(port)
