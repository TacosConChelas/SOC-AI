"""Tests for Collector poll cycle — mocked WazuhClient and Postgres connection."""

from __future__ import annotations

from unittest.mock import MagicMock

import fakeredis

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.collector.collector import Collector, WazuhClient, read_checkpoint, write_checkpoint


def _raw_alert(alert_id: str = "111.001", level: int = 10, ts: str = "2026-07-20T12:00:00.000+0000") -> dict:
    return {
        "id": alert_id,
        "timestamp": ts,
        "rule": {
            "id": "5710",
            "description": "SSH brute force",
            "level": level,
            "groups": ["authentication", "sshd"],
        },
        "agent": {"name": "host-01"},
        "data": {"srcip": "203.0.113.5"},
    }


def _make_bus() -> RedisBus:
    r = fakeredis.FakeRedis(decode_responses=True)
    bus = RedisBus(client=r, config=BusConfig(block_ms=100, socket_timeout_s=1.0))
    bus.ensure_group()
    return bus


def _mock_pg(checkpoint: str | None = None) -> MagicMock:
    pg = MagicMock()
    row = (checkpoint,) if checkpoint is not None else (None,)
    pg.execute.return_value.fetchone.return_value = row
    return pg


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------


def test_read_checkpoint_returns_none_when_empty() -> None:
    pg = MagicMock()
    pg.execute.return_value.fetchone.return_value = (None,)
    assert read_checkpoint(pg) is None


def test_read_checkpoint_returns_stored_timestamp() -> None:
    pg = MagicMock()
    pg.execute.return_value.fetchone.return_value = ("2026-07-20T12:00:00.000+0000",)
    assert read_checkpoint(pg) == "2026-07-20T12:00:00.000+0000"


def test_write_checkpoint_executes_and_commits() -> None:
    pg = MagicMock()
    write_checkpoint(pg, "2026-07-20T13:00:00.000+0000")
    pg.execute.assert_called_once()
    pg.commit.assert_called_once()
    sql: str = pg.execute.call_args[0][0]
    assert "UPDATE collector_checkpoint" in sql


# ---------------------------------------------------------------------------
# poll_once — happy path
# ---------------------------------------------------------------------------


def test_poll_once_publishes_alerts_to_bus() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    wazuh.fetch_alerts.return_value = [_raw_alert()]
    pg = _mock_pg()

    collector = Collector(wazuh=wazuh, bus=bus, pg_conn=pg)
    count = collector.poll_once()

    assert count == 1
    # event must be in the stream
    messages = bus._client.xrange(bus._config.events_stream)
    assert len(messages) == 1


def test_poll_once_advances_checkpoint_to_last_timestamp() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    ts = "2026-07-20T12:05:00.000+0000"
    wazuh.fetch_alerts.return_value = [_raw_alert(ts=ts)]
    pg = _mock_pg()

    Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()

    update_call = pg.execute.call_args_list[-1]
    assert ts in str(update_call)


def test_poll_once_uses_checkpoint_as_since_parameter() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    wazuh.fetch_alerts.return_value = []
    checkpoint = "2026-07-20T11:00:00.000+0000"
    pg = _mock_pg(checkpoint=checkpoint)

    Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()

    wazuh.fetch_alerts.assert_called_once_with(since_timestamp=checkpoint)


def test_poll_once_returns_count_of_published() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    wazuh.fetch_alerts.return_value = [
        _raw_alert("111.001"),
        _raw_alert("111.002"),
        _raw_alert("111.003"),
    ]
    pg = _mock_pg()

    count = Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()
    assert count == 3


def test_poll_once_empty_response_does_not_advance_checkpoint() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    wazuh.fetch_alerts.return_value = []
    pg = _mock_pg()

    Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()

    # Only one execute call: the checkpoint read — no UPDATE
    calls = [str(c) for c in pg.execute.call_args_list]
    assert not any("UPDATE" in c for c in calls)


# ---------------------------------------------------------------------------
# poll_once — quarantine path
# ---------------------------------------------------------------------------


def test_poll_once_quarantines_invalid_alert() -> None:
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    # alert missing required "timestamp" field → normalize raises KeyError
    wazuh.fetch_alerts.return_value = [{"id": "bad-001", "rule": {}, "agent": {}, "data": {}}]
    pg = _mock_pg()

    count = Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()

    assert count == 0
    assert bus._client.xlen(bus._config.events_stream) == 0


def test_poll_once_quarantine_does_not_stop_valid_alerts() -> None:
    """An invalid alert in the middle should be skipped; valid ones still publish."""
    bus = _make_bus()
    wazuh = MagicMock(spec=WazuhClient)
    bad = {"id": "bad", "rule": {}, "agent": {}, "data": {}}
    wazuh.fetch_alerts.return_value = [
        _raw_alert("111.001"),
        bad,
        _raw_alert("111.003"),
    ]
    pg = _mock_pg()

    count = Collector(wazuh=wazuh, bus=bus, pg_conn=pg).poll_once()
    assert count == 2
