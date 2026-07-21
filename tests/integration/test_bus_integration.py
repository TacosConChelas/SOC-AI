"""Integration tests for RedisBus — require a live Redis instance.

Run with: pytest -m integration
Auto-skipped when Redis is not reachable.
"""

from datetime import UTC, datetime

import pytest
import redis as redis_lib

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.contracts.event import UnifiedEvent


def _live_client() -> redis_lib.Redis | None:
    try:
        client = redis_lib.from_url(
            "redis://localhost:6379", decode_responses=True, socket_timeout=2.0
        )
        client.ping()
        return client
    except Exception:
        return None


@pytest.mark.integration
def test_bus_publish_read_ack_e2e() -> None:
    client = _live_client()
    if client is None:
        pytest.skip("no live Redis at localhost:6379")

    cfg = BusConfig(redis_url="redis://localhost:6379", block_ms=1_000)
    bus = RedisBus(client=client, config=cfg)
    bus.ensure_group()

    event = UnifiedEvent(
        event_id="integration-test-evt",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="integration-host",
        source_alert_id="wz-integration-1",
        event_type="NIDS",
        severity_hint="low",
        summary="Integration test event — safe to ignore",
        raw_ref="opensearch://soc-alerts/integration-test",
    )

    msg_id = bus.publish_event(event)
    assert msg_id

    pending = bus.read_one(consumer="integration-worker")
    assert pending is not None
    assert pending.event.event_id == "integration-test-evt"

    bus.ack(pending.msg_id)
    assert bus.read_one(consumer="integration-worker") is None
