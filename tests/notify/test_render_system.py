from __future__ import annotations

from core.notify.render import render_slack_system, render_telegram_system
from core.notify.system import SystemNotification


def _dead_letter(**over: object) -> SystemNotification:
    base: dict = dict(
        kind="dead_letter",
        sensor="edge-01",
        severity="high",
        reason="parse_failure",
        retry_count=2,
        detail="ValidationError",
    )
    base.update(over)
    return SystemNotification(**base)  # type: ignore[arg-type]


def _degradation() -> SystemNotification:
    return SystemNotification(
        kind="enrichment_degraded",
        sensor="edge-01",
        severity="high",
        reason="enrichment_degraded",
        retry_count=None,
        detail=None,
    )


# --- dead-letter render ---


def test_telegram_dead_letter_shows_unclassified_system() -> None:
    text = render_telegram_system(_dead_letter())
    assert "unclassified (system)" in text


def test_telegram_dead_letter_shows_reason_and_retries() -> None:
    text = render_telegram_system(_dead_letter())
    assert "parse_failure" in text
    assert "2" in text  # retry_count


def test_telegram_dead_letter_shows_sensor() -> None:
    text = render_telegram_system(_dead_letter())
    assert "edge-01" in text


def test_telegram_dead_letter_count_suffix_on_coalescing() -> None:
    text = render_telegram_system(_dead_letter(), count=5)
    assert "×5" in text


def test_slack_dead_letter_returns_mrkdwn_dict() -> None:
    msg = render_slack_system(_dead_letter())
    assert msg["mrkdwn"] is True
    text = str(msg["text"])
    assert "unclassified (system)" in text


def test_slack_dead_letter_count_suffix() -> None:
    text = str(render_slack_system(_dead_letter(), count=3)["text"])
    assert "×3" in text


# --- degradation render ---


def test_telegram_degradation_shows_context_degraded() -> None:
    text = render_telegram_system(_degradation())
    assert "enrichment degraded" in text.lower()


def test_slack_degradation_shows_context_degraded() -> None:
    text = str(render_slack_system(_degradation())["text"])
    assert "enrichment degraded" in text.lower()


# --- age-suppressed render (ADR-0004 Enmienda 2026-08, D-16) ---


def _age_suppressed() -> SystemNotification:
    return SystemNotification(
        kind="age_suppressed",
        sensor="edge-01",
        severity="high",
        reason="age_suppressed",
        retry_count=None,
        detail=None,
    )


def test_telegram_age_suppressed_shows_sensor_and_count() -> None:
    text = render_telegram_system(_age_suppressed(), count=161)
    assert "edge-01" in text
    assert "×161" in text


def test_slack_age_suppressed_mentions_age_cutoff() -> None:
    text = str(render_slack_system(_age_suppressed())["text"])
    assert "age" in text.lower()
