"""Unit tests for RedisBus — fakeredis[lua], no live Redis required."""

from datetime import UTC, datetime

import fakeredis
import pytest

from core.bus.config import BusConfig
from core.bus.streams import PendingEvent, RedisBus
from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord
from core.contracts.event import UnifiedEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def cfg() -> BusConfig:
    return BusConfig(block_ms=100)  # fast for tests, doesn't open a real connection


@pytest.fixture()
def fake_redis() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture()
def bus(fake_redis: fakeredis.FakeRedis, cfg: BusConfig) -> RedisBus:
    b = RedisBus(client=fake_redis, config=cfg)
    b.ensure_group()
    return b


@pytest.fixture()
def event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="evt-001",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="host-01",
        source_alert_id="wz-1234",
        event_type="NIDS",
        severity_hint="medium",
        summary="Test alert from host-01",
        raw_ref="opensearch://soc-alerts/wz-1234",
        src_ip="203.0.113.5",
    )


@pytest.fixture()
def dead_letter() -> DeadLetterRecord:
    return DeadLetterRecord(
        alert_id="alert-001",
        event_id="evt-001",
        source_module="wazuh",
        sensor="host-01",
        severity="medium",
        reason=DeadLetterReason.PARSE_FAILURE,
        retry_count=2,
        dead_lettered_at=datetime(2026, 7, 20, 12, 1, 0, tzinfo=UTC),
        detail="ValidationError: 2 errors on field classification",
    )


# ---------------------------------------------------------------------------
# ensure_group
# ---------------------------------------------------------------------------


def test_ensure_group_creates_groups(fake_redis: fakeredis.FakeRedis, cfg: BusConfig) -> None:
    bus = RedisBus(client=fake_redis, config=cfg)
    bus.ensure_group()  # must not raise
    # calling again must be idempotent (BUSYGROUP is swallowed)
    bus.ensure_group()


# ---------------------------------------------------------------------------
# publish_event + read_one + ack
# ---------------------------------------------------------------------------


def test_publish_event_adds_to_stream(bus: RedisBus, event: UnifiedEvent) -> None:
    msg_id = bus.publish_event(event)
    assert isinstance(msg_id, str)
    assert "-" in msg_id  # Redis stream ID format: <ms>-<seq>


def test_read_one_returns_pending_event(bus: RedisBus, event: UnifiedEvent) -> None:
    bus.publish_event(event)
    pending = bus.read_one(consumer="worker-1")
    assert pending is not None
    assert isinstance(pending, PendingEvent)
    assert pending.event.event_id == "evt-001"
    assert pending.event.sensor == "host-01"


def test_read_one_empty_stream_returns_none(bus: RedisBus) -> None:
    result = bus.read_one(consumer="worker-1")
    assert result is None


def test_ack_confirms_message(bus: RedisBus, event: UnifiedEvent) -> None:
    bus.publish_event(event)
    pending = bus.read_one(consumer="worker-1")
    assert pending is not None
    bus.ack(pending.msg_id)
    # After ack, the same consumer group should not see the message again
    assert bus.read_one(consumer="worker-1") is None


def test_ack_fails_loud_for_unknown_id(bus: RedisBus) -> None:
    with pytest.raises(RuntimeError, match="XACK failed"):
        bus.ack("0-1")


def test_read_one_deserializes_all_optional_fields(bus: RedisBus) -> None:
    full_event = UnifiedEvent(
        event_id="evt-full",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
        source_module="suricata",
        sensor="eth0",
        source_alert_id="eve-999",
        event_type="NIDS",
        severity_hint="high",
        summary="Suricata alert",
        raw_ref="opensearch://soc-alerts/eve-999",
        src_ip="1.2.3.4",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        signature="ET SCAN",
        rule_id="2024358",
        mitre_technique_ids=["T1046"],
    )
    bus.publish_event(full_event)
    pending = bus.read_one(consumer="worker-1")
    assert pending is not None
    assert pending.event.src_port == 54321
    assert pending.event.rule_id == "2024358"
    assert pending.event.mitre_technique_ids == ["T1046"]


# ---------------------------------------------------------------------------
# publish_dead_letter
# ---------------------------------------------------------------------------


def test_publish_dead_letter_adds_to_stream(bus: RedisBus, dead_letter: DeadLetterRecord) -> None:
    msg_id = bus.publish_dead_letter(dead_letter)
    assert isinstance(msg_id, str)
    assert "-" in msg_id


def test_publish_dead_letter_separate_from_events(
    bus: RedisBus, event: UnifiedEvent, dead_letter: DeadLetterRecord
) -> None:
    bus.publish_event(event)
    bus.publish_dead_letter(dead_letter)
    # read_one only reads from events stream, not dead-letter
    pending = bus.read_one(consumer="worker-1")
    assert pending is not None
    assert pending.event.event_id == "evt-001"
    # no second message in events stream
    assert bus.read_one(consumer="worker-1") is None


# ---------------------------------------------------------------------------
# claim_stale (XAUTOCLAIM)
# ---------------------------------------------------------------------------


def test_claim_stale_returns_unacked_message(bus: RedisBus, event: UnifiedEvent) -> None:
    bus.publish_event(event)
    # worker-1 reads but does NOT ack (simulates crash)
    original = bus.read_one(consumer="worker-1")
    assert original is not None

    # worker-2 claims stale messages idle >= 0ms
    stale = bus.claim_stale(consumer="worker-2", min_idle_ms=0)
    assert len(stale) == 1
    assert stale[0].event.event_id == "evt-001"


def test_claim_stale_empty_when_all_acked(bus: RedisBus, event: UnifiedEvent) -> None:
    bus.publish_event(event)
    pending = bus.read_one(consumer="worker-1")
    assert pending is not None
    bus.ack(pending.msg_id)
    stale = bus.claim_stale(consumer="worker-2", min_idle_ms=0)
    assert stale == []
