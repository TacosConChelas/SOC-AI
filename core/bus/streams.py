"""RedisBus — publish/consume over Redis Streams (soc:events, soc:deadletter)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import redis as redis_lib

from core.bus.config import BusConfig
from core.contracts.deadletter import DeadLetterRecord
from core.contracts.event import UnifiedEvent


@dataclass
class PendingEvent:
    msg_id: str
    event: UnifiedEvent


class RedisBus:
    def __init__(self, client: redis_lib.Redis, config: BusConfig) -> None:
        self._client = client
        self._config = config

    @classmethod
    def from_config(cls, config: BusConfig | None = None) -> RedisBus:
        cfg = config or BusConfig()
        client = redis_lib.from_url(
            cfg.redis_url,
            decode_responses=True,
            socket_timeout=cfg.socket_timeout_s,
        )
        return cls(client=client, config=cfg)

    def ensure_group(self) -> None:
        """Create consumer groups for both streams (idempotent — swallows BUSYGROUP)."""
        for stream in (self._config.events_stream, self._config.deadletter_stream):
            try:
                self._client.xgroup_create(
                    stream, self._config.consumer_group, id="0", mkstream=True
                )
            except redis_lib.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    def publish_event(self, event: UnifiedEvent) -> str:
        """Serialize, re-validate roundtrip, then XADD to soc:events."""
        payload = event.model_dump_json()
        UnifiedEvent.model_validate_json(payload)  # roundtrip guard at bus boundary
        return cast(str, self._client.xadd(self._config.events_stream, {"data": payload}))

    def read_one(self, consumer: str) -> PendingEvent | None:
        """XREADGROUP count=1; returns None on timeout or empty stream."""
        raw = self._client.xreadgroup(
            groupname=self._config.consumer_group,
            consumername=consumer,
            streams={self._config.events_stream: ">"},
            count=1,
            block=self._config.block_ms,
        )
        result: list[Any] = cast(list[Any], raw)
        if not result:
            return None
        _stream, messages = result[0]
        if not messages:
            return None
        msg_id, fields = messages[0]
        event = UnifiedEvent.model_validate_json(fields["data"])
        return PendingEvent(msg_id=str(msg_id), event=event)

    def ack(self, msg_id: str) -> None:
        """XACK — fail-loud if message was not in the PEL."""
        count = self._client.xack(
            self._config.events_stream, self._config.consumer_group, msg_id
        )
        if not count:
            raise RuntimeError(f"XACK failed for msg_id={msg_id!r} — not in PEL")

    def claim_stale(
        self,
        consumer: str,
        min_idle_ms: int | None = None,
        count: int = 10,
    ) -> list[PendingEvent]:
        """XAUTOCLAIM: transfer unacknowledged messages idle >= min_idle_ms to consumer."""
        idle = min_idle_ms if min_idle_ms is not None else self._config.claim_min_idle_ms
        raw = self._client.xautoclaim(
            name=self._config.events_stream,
            groupname=self._config.consumer_group,
            consumername=consumer,
            min_idle_time=idle,
            start_id="0-0",
            count=count,
        )
        # redis-py 8: [next_start_id, [(msg_id, fields), ...], [deleted_ids]]
        _next_id, messages, _deleted = cast(tuple[Any, list[Any], list[Any]], raw)
        pending: list[PendingEvent] = []
        for msg_id, fields in messages:
            event = UnifiedEvent.model_validate_json(fields["data"])
            pending.append(PendingEvent(msg_id=str(msg_id), event=event))
        return pending

    def publish_dead_letter(self, record: DeadLetterRecord) -> str:
        """XADD to soc:deadletter stream."""
        payload = record.model_dump_json()
        return cast(str, self._client.xadd(self._config.deadletter_stream, {"data": payload}))
