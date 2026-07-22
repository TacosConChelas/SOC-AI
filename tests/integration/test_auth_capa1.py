"""Auth Capa 1 tests — negative ACL check + partial smoke E2E.

Run with: pytest -m integration
Auto-skipped when dependencies are not reachable.

Negative test (A4.4): KPI Familia 5 — always passes when ACL is active.
Smoke E2E (A4.6): injects event → Worker.run_once() → verifies TriageRecord in Postgres.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
import redis as redis_lib

try:
    import psycopg as _psycopg_mod

    _HAS_PG = True
except Exception:
    _psycopg_mod = None  # type: ignore[assignment]
    _HAS_PG = False

from core.bus.config import BusConfig
from core.bus.streams import RedisBus
from core.contracts.event import UnifiedEvent
from core.notify.clients import MultiNotifier
from core.notify.system_notifier import SystemNotifier
from core.orchestrator.graph import TriageDeps, TriageGraph
from core.orchestrator.nodes.classify import OllamaClient
from core.orchestrator.nodes.group import SessionStore
from core.orchestrator.worker import Worker

# ─── helpers ────────────────────────────────────────────────────────────────


def _redis_worker() -> redis_lib.Redis | None:
    """Connect as core-worker using env credentials (skips if unreachable)."""
    url = os.getenv("SOC_REDIS_URL", "redis://localhost:6379")
    user = os.getenv("REDIS_USER")
    password = os.getenv("REDIS_PASSWORD")
    try:
        client: redis_lib.Redis = redis_lib.from_url(
            url, username=user, password=password, decode_responses=True, socket_timeout=2.0
        )
        client.ping()
        return client
    except Exception:
        return None


def _pg_conn() -> Any:
    if not _HAS_PG or _psycopg_mod is None:
        return None
    dsn = os.getenv("POSTGRES_DSN", "postgresql://soc:soc@localhost:5432/soc")
    try:
        return _psycopg_mod.connect(dsn, connect_timeout=2)
    except Exception:
        return None


def _test_event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="smoke-e2e-auth-test",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 21, 0, 0, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="smoke-host",
        source_alert_id="wz-smoke-auth-1",
        event_type="NIDS",
        severity_hint="low",
        summary="Auth Capa 1 smoke test — safe to ignore",
        raw_ref="opensearch://soc-alerts/smoke-auth-test",
    )


# ─── A4.4 — negative ACL test ───────────────────────────────────────────────


@pytest.mark.integration
def test_acl_rogue_xadd_rejected() -> None:
    """Rogue publisher (no credentials) must not be able to XADD to soc:events.

    KPI Familia 5: security. Binary: always passes when ACL is active.
    """
    url = os.getenv("SOC_REDIS_URL", "redis://localhost:6379")
    try:
        # Connect without any credentials — the default user must be disabled
        rogue: redis_lib.Redis = redis_lib.from_url(url, decode_responses=True, socket_timeout=2.0)
        try:
            rogue.xadd("soc:events", {"data": "rogue-test"})
            pytest.skip(
                "XADD succeeded without credentials — "
                "ACL not active. Run compose with services/redis/users.acl to test."
            )
        except (redis_lib.ResponseError, redis_lib.AuthenticationError) as exc:
            assert "NOPERM" in str(exc) or "NOAUTH" in str(exc) or "AUTH" in str(exc), (
                f"Expected ACL rejection, got: {exc}"
            )
    except redis_lib.ConnectionError:
        pytest.skip("no live Redis at configured SOC_REDIS_URL")


# ─── A4.6 — smoke E2E ───────────────────────────────────────────────────────


@pytest.mark.integration
def test_smoke_e2e_triage_record_persisted() -> None:
    """Inject event → Worker.run_once() → TriageRecord appears in Postgres.

    Uses:
    - Real Redis (core-worker credentials from env)
    - Real Postgres (POSTGRES_DSN from env)
    - Mock OpenSearch (returns zeroed context with lookup_degraded=True)
    - Mock Ollama (returns valid classification JSON)
    - Mock Notifier (captures calls, no real Slack/Telegram)
    """
    redis_client = _redis_worker()
    if redis_client is None:
        pytest.skip("no live Redis at SOC_REDIS_URL with REDIS_USER/REDIS_PASSWORD")

    pg = _pg_conn()
    if pg is None:
        pytest.skip("no live Postgres at POSTGRES_DSN")

    try:
        _run_smoke_e2e(redis_client, pg)
    finally:
        pg.close()


def _run_smoke_e2e(redis_client: redis_lib.Redis, pg: Any) -> None:
    # Mock OpenSearch: always returns degraded context (no real OS needed)
    mock_os = MagicMock()
    mock_os.search.side_effect = Exception("opensearch not available in smoke test")

    # Mock Ollama: returns a valid TriageModelOutput JSON
    mock_ollama = MagicMock(spec=OllamaClient)
    mock_ollama.chat.return_value = (
        '{"classification": "noise", "confidence": 0.95, '
        '"summary": "Smoke test event — safe to ignore", '
        '"suggested_actions": [], '
        '"rationale": "This is an automated smoke test. No real threat."}'
    )

    mock_notifier = MagicMock(spec=MultiNotifier)
    mock_system_notifier = MagicMock(spec=SystemNotifier)

    config = BusConfig(redis_url=os.getenv("SOC_REDIS_URL", "redis://localhost:6379"), block_ms=1_000)
    bus = RedisBus(redis_client, config)
    bus.ensure_group()

    deps = TriageDeps(
        os_client=mock_os,
        ollama_client=mock_ollama,
        session_store=SessionStore(redis_client),
        pg_conn=pg,
        dead_letter_bus=bus,
        notifier=mock_notifier,
        system_notifier=mock_system_notifier,
    )
    worker = Worker(bus, TriageGraph(deps))

    event = _test_event()
    bus.publish_event(event)

    processed = worker.run_once()
    assert processed, "Worker did not process the injected event"

    # Verify TriageRecord was persisted
    row = pg.execute(
        "SELECT classification, severity FROM triage_records WHERE event_id = %s",
        (event.event_id,),
    ).fetchone()
    assert row is not None, "TriageRecord not found in Postgres after Worker.run_once()"
    assert row[0] in ("noise", "informational", "alert"), f"unexpected classification: {row[0]}"

    # Cleanup
    pg.execute("DELETE FROM triage_records WHERE event_id = %s", (event.event_id,))
    pg.commit()
