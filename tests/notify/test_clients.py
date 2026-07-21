from __future__ import annotations

import httpx

from core.contracts.triage import Classification, Severity
from core.notify.clients import MultiNotifier, SlackNotifier, TelegramNotifier
from core.notify.content import NotificationContent


def _content() -> NotificationContent:
    return NotificationContent(
        severity=Severity.HIGH,
        classification=Classification.ALERT,
        confidence=0.91,
        summary="scan",
        rationale="why",
        src_ip_seen_before=True,
        related_events_24h=1,
        distinct_rules_from_src_24h=1,
        events_last_10min=1,
        src_in_allowlist=False,
        suggested_actions=("act",),
        matched_rule="r1",
        src_ip="1.2.3.4",
        dst_ip=None,
        sensor="s1",
        incident_group_key="g1",
        flags=(),
    )


def _capture() -> tuple[list[httpx.Request], httpx.Client]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_slack_posts_to_override_url_with_bearer_and_channel() -> None:
    seen, client = _capture()
    SlackNotifier("tok-123", "#soc-incidents", api_url="https://mock/slack", client=client).send(_content())
    assert len(seen) == 1
    req = seen[0]
    assert str(req.url) == "https://mock/slack"
    assert req.headers["authorization"] == "Bearer tok-123"
    body = req.content.decode()
    assert '"channel"' in body and "soc-incidents" in body


def test_telegram_posts_to_sendmessage_with_chat_id() -> None:
    seen, client = _capture()
    TelegramNotifier("bot-tok", "42", api_base="https://mock", client=client).send(_content())
    assert len(seen) == 1
    req = seen[0]
    assert str(req.url) == "https://mock/botbot-tok/sendMessage"
    body = req.content.decode()
    assert '"chat_id"' in body and "42" in body


def test_multinotifier_fans_out_to_all_channels() -> None:
    seen_s, client_s = _capture()
    seen_t, client_t = _capture()
    multi = MultiNotifier(
        [
            SlackNotifier("t", "#c", api_url="https://mock/s", client=client_s),
            TelegramNotifier("t", "1", api_base="https://mock", client=client_t),
        ]
    )
    multi.send(_content())
    assert len(seen_s) == 1
    assert len(seen_t) == 1


def test_multinotifier_empty_is_noop() -> None:
    MultiNotifier([]).send(_content())  # must not raise


def test_from_env_builds_only_configured_channels(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SLACK_BOT_TOKEN", "tok")
    monkeypatch.setenv("SLACK_CHANNEL", "#soc-incidents")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    multi = MultiNotifier.from_env()
    assert len(multi.channels) == 1
    assert isinstance(multi.channels[0], SlackNotifier)
