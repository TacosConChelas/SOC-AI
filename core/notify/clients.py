"""Slack/Telegram notifiers — httpx puro, sin SDK. URLs override por env."""

from __future__ import annotations

import os

import httpx

from core.notify.content import NotificationContent
from core.notify.render import render_slack, render_slack_system, render_telegram, render_telegram_system
from core.notify.system import SystemNotification

_SLACK_DEFAULT = "https://slack.com/api/chat.postMessage"
_TELEGRAM_DEFAULT = "https://api.telegram.org"


class SlackNotifier:
    def __init__(
        self, token: str, channel: str, *, api_url: str | None = None, client: httpx.Client | None = None
    ) -> None:
        self._token = token
        self._channel = channel
        self._url = api_url or os.getenv("SLACK_API_URL") or _SLACK_DEFAULT
        self._client = client or httpx.Client(timeout=10.0)

    def _post(self, payload: dict[str, object]) -> None:
        resp = self._client.post(self._url, headers={"Authorization": f"Bearer {self._token}"}, json=payload)
        resp.raise_for_status()

    def send(self, content: NotificationContent) -> None:
        self._post({"channel": self._channel, **render_slack(content)})

    def send_system(self, notif: SystemNotification, count: int = 1) -> None:
        self._post({"channel": self._channel, **render_slack_system(notif, count=count)})


class TelegramNotifier:
    def __init__(
        self, token: str, chat_id: str, *, api_base: str | None = None, client: httpx.Client | None = None
    ) -> None:
        self._token = token
        self._chat_id = chat_id
        self._base = (api_base or os.getenv("TELEGRAM_API_BASE") or _TELEGRAM_DEFAULT).rstrip("/")
        self._client = client or httpx.Client(timeout=10.0)

    def _post_text(self, text: str) -> None:
        url = f"{self._base}/bot{self._token}/sendMessage"
        resp = self._client.post(url, json={"chat_id": self._chat_id, "text": text})
        resp.raise_for_status()

    def send(self, content: NotificationContent) -> None:
        self._post_text(render_telegram(content))

    def send_system(self, notif: SystemNotification, count: int = 1) -> None:
        self._post_text(render_telegram_system(notif, count=count))


class MultiNotifier:
    def __init__(self, channels: list[SlackNotifier | TelegramNotifier]) -> None:
        self.channels = channels

    def send(self, content: NotificationContent) -> None:
        for ch in self.channels:
            ch.send(content)

    def send_system(self, notif: SystemNotification, count: int = 1) -> None:
        for ch in self.channels:
            ch.send_system(notif, count=count)

    @classmethod
    def from_env(cls) -> MultiNotifier:
        channels: list[SlackNotifier | TelegramNotifier] = []
        slack_token = os.getenv("SLACK_BOT_TOKEN")
        slack_channel = os.getenv("SLACK_CHANNEL")
        if slack_token and slack_channel:
            channels.append(SlackNotifier(slack_token, slack_channel))
        tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        tg_chat = os.getenv("TELEGRAM_CHAT_ID")
        if tg_token and tg_chat:
            channels.append(TelegramNotifier(tg_token, tg_chat))
        return cls(channels)
