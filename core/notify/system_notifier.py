"""SystemNotifier: coalescing buffer + fan-out to #soc-system channels."""

from __future__ import annotations

import os
import time

from core.contracts.deadletter import DeadLetterRecord
from core.contracts.event import UnifiedEvent
from core.notify.clients import MultiNotifier, SlackNotifier, TelegramNotifier
from core.notify.system import project_age_suppressed, project_dead_letter, project_degradation


class CoalescingBuffer:
    """One message per key per window. Fires on first event; re-fires after window with total count.

    # ponytail: in-process dict, resets on restart — acceptable for pipeline-health telemetry
    """

    def __init__(self, window_s: float = 60.0) -> None:
        self._window = window_s
        self._counts: dict[tuple[str, str], int] = {}
        self._window_starts: dict[tuple[str, str], float] = {}

    def push(self, key: tuple[str, str], *, now: float | None = None) -> int | None:
        """Return count to send (fire) or None (suppress).

        First event in window fires with count=1.
        Subsequent events in same window are suppressed and accumulated.
        First event after window expiry fires with total count from closed window.
        """
        t = now if now is not None else time.monotonic()
        start = self._window_starts.get(key)

        if start is None:
            # First ever event for this key
            self._counts[key] = 1
            self._window_starts[key] = t
            return 1
        elif t - start >= self._window:
            # Window expired: fire with accumulated count, open new window
            prev_count = self._counts[key]
            self._counts[key] = 1
            self._window_starts[key] = t
            return prev_count
        else:
            # Within window: accumulate, suppress
            self._counts[key] += 1
            return None


class SystemNotifier:
    """Wraps MultiNotifier targeting #soc-system, with coalescing per (reason, sensor) key."""

    def __init__(self, multi: MultiNotifier, *, window_s: float = 60.0) -> None:
        self._multi = multi
        self._buf = CoalescingBuffer(window_s)
        # Dedicated buffer (ADR-0004 Enmienda 2026-08): a CloudTrail backlog can suppress
        # thousands of events by age alone, independent of dead-letter/degradation traffic.
        self._age_buf = CoalescingBuffer(window_s)

    def notify_dead_letter(self, record: DeadLetterRecord, *, now: float | None = None) -> None:
        notif = project_dead_letter(record)
        key = (record.reason.value, record.sensor)
        count = self._buf.push(key, now=now)
        if count is not None:
            self._multi.send_system(notif, count=count)

    def notify_degradation(self, event: UnifiedEvent, *, now: float | None = None) -> None:
        notif = project_degradation(event)
        key = ("enrichment_degraded", event.sensor)
        count = self._buf.push(key, now=now)
        if count is not None:
            self._multi.send_system(notif, count=count)

    def notify_age_suppressed(self, event: UnifiedEvent, *, now: float | None = None) -> None:
        notif = project_age_suppressed(event)
        key = ("age_suppressed", event.sensor)
        count = self._age_buf.push(key, now=now)
        if count is not None:
            self._multi.send_system(notif, count=count)

    @classmethod
    def from_env(cls) -> SystemNotifier:
        channels: list[SlackNotifier | TelegramNotifier] = []
        slack_token = os.getenv("SLACK_BOT_TOKEN")
        slack_channel = os.getenv("SLACK_SYSTEM_CHANNEL")
        if slack_token and slack_channel:
            channels.append(SlackNotifier(slack_token, slack_channel))
        tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
        tg_chat = os.getenv("TELEGRAM_SYSTEM_CHAT_ID")
        if tg_token and tg_chat:
            channels.append(TelegramNotifier(tg_token, tg_chat))
        return cls(MultiNotifier(channels))
