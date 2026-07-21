"""Collector — polls Wazuh API, normalizes alerts, publishes to bus, checkpoints in Postgres."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from core.bus.streams import RedisBus
from core.collector.normalizer import normalize
from core.observability.metrics import COLLECTOR_PUBLISHED, COLLECTOR_QUARANTINED

log = logging.getLogger(__name__)

_WAZUH_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
_WAZUH_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
_WAZUH_PASS = os.getenv("WAZUH_API_PASSWORD", "")
_PAGE_SIZE = 100


class WazuhClient:
    """Minimal Wazuh v4 REST client — JWT auth + paginated alert fetch."""

    def __init__(
        self,
        base_url: str = _WAZUH_URL,
        user: str = _WAZUH_USER,
        password: str = _WAZUH_PASS,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._user = user
        self._password = password
        self._token: str | None = None

    def _authenticate(self, client: httpx.Client) -> str:
        resp = client.post(
            f"{self._base}/security/user/authenticate",
            auth=(self._user, self._password),
        )
        resp.raise_for_status()
        return str(resp.json()["data"]["token"])

    def fetch_alerts(
        self,
        since_timestamp: str | None = None,
        limit: int = _PAGE_SIZE,
    ) -> list[dict[str, Any]]:
        """Return up to `limit` alerts newer than since_timestamp (ISO), sorted ascending.

        Handles 401 by re-authenticating once.
        TLS: set WAZUH_CA_BUNDLE to the Wazuh root CA path (compose volume /certs/root-ca.pem).
        """
        params: dict[str, Any] = {"limit": limit, "sort": "+timestamp"}
        if since_timestamp:
            params["q"] = f"timestamp>{since_timestamp}"

        # Wazuh ships with a self-signed cert. Set WAZUH_CA_BUNDLE to the path of
        # the Wazuh root CA (e.g. /certs/root-ca.pem from the compose volume).
        # Leaving it unset keeps verify=True (system CA store).
        ca = os.getenv("WAZUH_CA_BUNDLE")
        verify: bool | str = ca if ca else True

        with httpx.Client(verify=verify, timeout=30.0) as client:
            if self._token is None:
                self._token = self._authenticate(client)

            def _get() -> httpx.Response:
                return client.get(
                    f"{self._base}/alerts",
                    headers={"Authorization": f"Bearer {self._token}"},
                    params=params,
                )

            resp = _get()
            if resp.status_code == 401:
                self._token = self._authenticate(client)
                resp = _get()
            resp.raise_for_status()

        items: list[dict[str, Any]] = resp.json().get("data", {}).get("affected_items", [])
        return items


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
