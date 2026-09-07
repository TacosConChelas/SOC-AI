"""Collector — polls the Wazuh Indexer (OpenSearch), normalizes alerts, publishes to bus, checkpoints in Postgres.

D-01: in Wazuh 4.x, alerts live in the Wazuh Indexer (OpenSearch, index
wazuh-alerts-4.x-*) — the Manager REST API on port 55000 does not serve alerts
at all. See .Knowledge/decisions.md (D-01, task 23) and
.Knowledge/Diagrams/Diagram_L3_Ingestion_Bus.md §L3-a.
"""

from __future__ import annotations

import logging
from typing import Any

from core.bus.streams import RedisBus
from core.collector.normalizer import normalize
from core.observability.metrics import COLLECTOR_PUBLISHED, COLLECTOR_QUARANTINED

log = logging.getLogger(__name__)

_ALERTS_INDEX = "wazuh-alerts-4.x-*"
_PAGE_SIZE = 100


class WazuhClient:
    """Wazuh Indexer (OpenSearch) client — search_after pagination over wazuh-alerts-4.x-*.

    Takes an already-constructed opensearch-py client, same pattern as the
    enrich node / orchestrator entrypoint (one OpenSearch client per process,
    injected in rather than built from raw credentials here).
    """

    def __init__(self, os_client: Any, index: str = _ALERTS_INDEX) -> None:
        self._os = os_client
        self._index = index

    def fetch_alerts(
        self,
        since_timestamp: str | None = None,
        limit: int = _PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """Return up to `limit` alerts strictly after since_timestamp, sorted ascending.

        Pagination via sort [@timestamp, id] + search_after (no scroll API). The
        Postgres checkpoint only tracks the timestamp component; the empty-string
        id floor keeps this a strict "timestamp >" resume, matching the previous
        semantics (at-least-once delivery, per D-01 / task 23).
        """
        body: dict[str, Any] = {
            "size": limit,
            "query": {"match_all": {}},
            "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
        }
        if since_timestamp is not None:
            body["search_after"] = [since_timestamp, ""]

        resp = self._os.search(index=self._index, body=body)
        hits: list[dict[str, Any]] = resp["hits"]["hits"]
        return [hit["_source"] for hit in hits]


def read_checkpoint(conn: Any) -> str | None:
    """Return the ISO timestamp of the last published alert, or None if no checkpoint."""
    row = conn.execute("SELECT last_alert_id FROM collector_checkpoint WHERE id = 1").fetchone()
    return str(row[0]) if row and row[0] else None


def write_checkpoint(conn: Any, timestamp: str) -> None:
    """Advance the checkpoint to timestamp and commit."""
    conn.execute(
        "UPDATE collector_checkpoint SET last_alert_id = %s, updated_at = NOW() WHERE id = 1",
        (timestamp,),
    )
    conn.commit()


class Collector:
    """One poll cycle: read checkpoint → fetch alerts → normalize → publish → advance checkpoint."""

    def __init__(self, wazuh: WazuhClient, bus: RedisBus, pg_conn: Any) -> None:
        self._wazuh = wazuh
        self._bus = bus
        self._pg = pg_conn

    def poll_once(self) -> int:
        """Fetch one page of alerts and publish them. Returns the number of events published."""
        checkpoint = read_checkpoint(self._pg)
        raw_alerts = self._wazuh.fetch_alerts(since_timestamp=checkpoint)

        published = 0
        last_ts: str | None = None

        for raw in raw_alerts:
            try:
                event = normalize(raw)
            except (ValueError, KeyError, TypeError) as exc:
                log.warning("quarantine: normalize failed for alert %s — %s", raw.get("id"), exc)
                COLLECTOR_QUARANTINED.inc()
                continue

            try:
                self._bus.publish_event(event)
            except Exception as exc:
                log.error("publish failed for alert %s: %s", raw.get("id"), exc)
                break  # stop; checkpoint stays at last success to avoid skipping events

            published += 1
            COLLECTOR_PUBLISHED.inc()
            last_ts = raw.get("timestamp")

        if last_ts:
            write_checkpoint(self._pg, last_ts)

        return published
