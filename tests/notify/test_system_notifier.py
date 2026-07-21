from __future__ import annotations

from datetime import UTC, datetime

import httpx

from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord
from core.contracts.event import UnifiedEvent
from core.notify.clients import MultiNotifier, SlackNotifier, TelegramNotifier
from core.notify.system import SystemNotification
from core.notify.system_notifier import CoalescingBuffer, SystemNotifier


# ---------------------------------------------------------------------------
# CoalescingBuffer
# ---------------------------------------------------------------------------


def test_coalescing_first_event_fires() -> None:
    buf = CoalescingBuffer(window_s=60.0)
    key = ("parse_failure", "edge-01")
    result = buf.push(key, now=0.0)
    assert result == 1


def test_coalescing_subsequent_in_window_suppressed() -> None:
    buf = CoalescingBuffer(window_s=60.0)
    key = ("parse_failure", "edge-01")
    buf.push(key, now=0.0)
    results = [buf.push(key, now=float(i)) for i in range(1, 5)]
    assert all(r is None for r in results)


def test_coalescing_after_window_fires_with_accumulated_count() -> None:
    buf = CoalescingBuffer(window_s=60.0)
    key = ("parse_failure", "edge-01")
    buf.push(key, now=0.0)  # fires count=1
    for i in range(1, 5):
        buf.push(key, now=float(i))  # suppressed (4 events)
    # window started at t=0, expires at t=60; total in window = 5
    result = buf.push(key, now=65.0)
    assert result == 5


def test_coalescing_distinct_keys_dont_suppress_each_other() -> None:
    buf = CoalescingBuffer(window_s=60.0)
    key1 = ("parse_failure", "edge-01")
    key2 = ("model_unavailable", "edge-01")
    r1 = buf.push(key1, now=0.0)
    r2 = buf.push(key2, now=0.0)
    assert r1 == 1
    assert r2 == 1


# ---------------------------------------------------------------------------
# clients.send_system() — SlackNotifier and TelegramNotifier
# ---------------------------------------------------------------------------


def _notif() -> SystemNotification:
    return SystemNotification(
        kind="dead_letter",
        sensor="edge-01",
        severity="high",
        reason="parse_failure",
        retry_count=2,
        detail="ValidationError",
    )


def _capture() -> tuple[list[httpx.Request], httpx.Client]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_slack_send_system_posts_with_bearer() -> None:
    seen, client = _capture()
    SlackNotifier("tok", "#soc-system", api_url="https://mock/slack", client=client).send_system(_notif())
    assert len(seen) == 1
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert "unclassified (system)" in seen[0].content.decode()


def test_telegram_send_system_posts_to_sendmessage() -> None:
    seen, client = _capture()
    TelegramNotifier("tok", "99", api_base="https://mock", client=client).send_system(_notif())
    assert len(seen) == 1
    assert "sendMessage" in str(seen[0].url)
    assert "unclassified (system)" in seen[0].content.decode()


def test_multinotifier_send_system_fans_out() -> None:
    seen_s, client_s = _capture()
    seen_t, client_t = _capture()
    multi = MultiNotifier(
        [
            SlackNotifier("t", "#s", api_url="https://mock/s", client=client_s),
            TelegramNotifier("t", "1", api_base="https://mock", client=client_t),
        ]
    )
    multi.send_system(_notif())
    assert len(seen_s) == 1
    assert len(seen_t) == 1


# ---------------------------------------------------------------------------
# SystemNotifier — integration
# ---------------------------------------------------------------------------


def _dead_letter_record() -> DeadLetterRecord:
    return DeadLetterRecord(
        alert_id="wz-1",
        event_id="e-1",
        source_module="wazuh",
        sensor="edge-01",
        severity="high",
        reason=DeadLetterReason.PARSE_FAILURE,
        retry_count=2,
        dead_lettered_at=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        detail="ValidationError",
    )


def _event() -> UnifiedEvent:
    return UnifiedEvent(
        event_id="e-1",
        schema_version="unified-event@1",
        timestamp=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        source_module="wazuh",
        sensor="edge-01",
        source_alert_id="wz-1",
        event_type="NIDS",
        severity_hint="high",
        summary="scan",
        raw_ref="opensearch://x/wz-1",
        src_ip="203.0.113.5",
        rule_id="2024358",
    )


def test_system_notifier_dead_letter_fires_first_in_window() -> None:
    seen, client = _capture()
    multi = MultiNotifier([SlackNotifier("tok", "#sys", api_url="https://mock/s", client=client)])
    sn = SystemNotifier(multi, window_s=60.0)
    sn.notify_dead_letter(_dead_letter_record(), now=0.0)
    assert len(seen) == 1


def test_system_notifier_dead_letter_suppresses_in_window() -> None:
    seen, client = _capture()
    multi = MultiNotifier([SlackNotifier("tok", "#sys", api_url="https://mock/s", client=client)])
    sn = SystemNotifier(multi, window_s=60.0)
    sn.notify_dead_letter(_dead_letter_record(), now=0.0)
    sn.notify_dead_letter(_dead_letter_record(), now=1.0)
    sn.notify_dead_letter(_dead_letter_record(), now=2.0)
    assert len(seen) == 1  # only first fires


def test_system_notifier_dead_letter_fires_after_window_with_count() -> None:
    seen, client = _capture()
    multi = MultiNotifier([SlackNotifier("tok", "#sys", api_url="https://mock/s", client=client)])
    sn = SystemNotifier(multi, window_s=60.0)
    sn.notify_dead_letter(_dead_letter_record(), now=0.0)
    sn.notify_dead_letter(_dead_letter_record(), now=1.0)  # suppressed → count=2
    sn.notify_dead_letter(_dead_letter_record(), now=65.0)  # new window: fires with count=2
    assert len(seen) == 2
    assert "×2" in seen[1].content.decode()


def test_system_notifier_degradation_fires() -> None:
    seen, client = _capture()
    multi = MultiNotifier([SlackNotifier("tok", "#sys", api_url="https://mock/s", client=client)])
    sn = SystemNotifier(multi, window_s=60.0)
    sn.notify_degradation(_event(), now=0.0)
    assert len(seen) == 1
    assert "enrichment degraded" in seen[0].content.decode().lower()


def test_from_env_builds_system_notifier(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SLACK_BOT_TOKEN", "tok")
    monkeypatch.setenv("SLACK_SYSTEM_CHANNEL", "#soc-system")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    sn = SystemNotifier.from_env()
    assert len(sn._multi.channels) == 1
    assert isinstance(sn._multi.channels[0], SlackNotifier)
