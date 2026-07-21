"""Group node — session-based incident grouping backed by Redis."""

import hashlib
import uuid
from dataclasses import dataclass

import redis

from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, Severity

_RANK: dict[Classification, int] = {
    Classification.NOISE: 0,
    Classification.INFORMATIONAL: 1,
    Classification.ALERT: 2,
}


@dataclass(frozen=True)
class SessionState:
    incident_group_key: str
    is_new_session: bool
    escalated: bool


class SessionStore:
    def __init__(self, client: redis.Redis, gap_seconds: int = 300) -> None:
        self._r = client
        self._ttl = gap_seconds

    def fold(
        self,
        event: UnifiedEvent,
        classification: Classification,
        severity: Severity,
    ) -> SessionState:
        sig = f"{event.src_ip or event.sensor}:{event.rule_id}"
        key = "session:" + hashlib.sha256(sig.encode()).hexdigest()

        existing: dict[str, str] = self._r.hgetall(key)  # type: ignore[assignment]

        if not existing:
            group_key = str(uuid.uuid4())
            self._r.hset(key, mapping={"group_key": group_key, "opening_cls": classification})
            self._r.expire(key, self._ttl)
            return SessionState(incident_group_key=group_key, is_new_session=True, escalated=False)

        self._r.expire(key, self._ttl)
        group_key = existing["group_key"]
        escalated = _RANK[classification] > _RANK[Classification(existing["opening_cls"])]
        return SessionState(incident_group_key=group_key, is_new_session=False, escalated=escalated)
