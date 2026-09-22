"""Group node — session-based incident grouping backed by Redis."""

import hashlib
from dataclasses import dataclass

import redis

from core.contracts.event import UnifiedEvent, matched_rule_of
from core.contracts.triage import Classification, Severity
from core.observability.metrics import GROUP_TOTAL

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
    session_was_notified: bool = False
    session_key: str = ""  # Redis hash key — pass to SessionStore.mark_notified()


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
        # ADR-0002: signature = src_ip + matched_rule (host fallback: sensor + matched_rule).
        # matched_rule_of unifies rule_id/signature/event_type — same helper enrich uses.
        sig = f"{event.src_ip or event.sensor}:{matched_rule_of(event)}"
        key = "session:" + hashlib.sha256(sig.encode()).hexdigest()

        existing: dict[str, str] = self._r.hgetall(key)  # type: ignore[assignment]

        if not existing:
            first_seen_unix = int(event.timestamp.timestamp())
            group_key = self._incident_group_key(sig, first_seen_unix)
            self._r.hset(
                key,
                mapping={
                    "group_key": group_key,
                    "opening_cls": classification,
                    "notified": "0",
                    "first_seen_unix": str(first_seen_unix),
                },
            )
            self._r.expire(key, self._ttl)
            GROUP_TOTAL.labels(action="new_session").inc()
            return SessionState(
                incident_group_key=group_key,
                is_new_session=True,
                escalated=False,
                session_was_notified=False,
                session_key=key,
            )

        self._r.expire(key, self._ttl)
        group_key = existing["group_key"]
        escalated = _RANK[classification] > _RANK[Classification(existing["opening_cls"])]
        was_notified = existing.get("notified", "0") == "1"
        GROUP_TOTAL.labels(action="folded").inc()
        return SessionState(
            incident_group_key=group_key,
            is_new_session=False,
            escalated=escalated,
            session_was_notified=was_notified,
            session_key=key,
        )

    @staticmethod
    def _incident_group_key(signature: str, first_seen_unix: int) -> str:
        """ADR-0002 task 26: sha1(signature|first_seen_unix) — deterministic, not random.

        Same signature + first_seen must always yield the same key, independent of
        which process or Redis instance computes it.
        """
        return hashlib.sha1(f"{signature}|{first_seen_unix}".encode()).hexdigest()

    def mark_notified(self, session_key: str) -> None:
        """Set the notified flag for a session. Called after a notification is sent."""
        self._r.hset(session_key, "notified", "1")
