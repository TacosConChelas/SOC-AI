from __future__ import annotations

from core.contracts.triage import Classification, Severity
from core.notify.content import NotificationContent
from core.notify.render import render_slack, render_telegram


def _content(**over: object) -> NotificationContent:
    base: dict = dict(
        severity=Severity.HIGH, classification=Classification.ALERT, confidence=0.91,
        summary="Nmap scan from 203.0.113.5", rationale="Repeated NSE <activity>",
        src_ip_seen_before=True, related_events_24h=47, distinct_rules_from_src_24h=1,
        events_last_10min=5, src_in_allowlist=False,
        suggested_actions=("Block 203.0.113.5 at the edge",),
        matched_rule="2024358", src_ip="203.0.113.5", dst_ip="10.0.0.1",
        sensor="edge-01", incident_group_key="9c2f4a8e0b21", flags=("severity_floor",),
    )
    base.update(over)
    return NotificationContent(**base)  # type: ignore[arg-type]


def test_telegram_defangs_ips() -> None:
    text = render_telegram(_content())
    assert "203[.]0[.]113[.]5" in text
    assert "203.0.113.5" not in text


def test_telegram_shows_both_severity_and_classification() -> None:
    text = render_telegram(_content())
    assert "HIGH" in text
    assert "ALERT" in text


def test_telegram_includes_emoji_and_evidence_and_actions() -> None:
    text = render_telegram(_content())
    assert "🟠" in text  # high
    assert "47" in text  # related_events_24h
    assert "Block 203[.]0[.]113[.]5 at the edge" in text  # action, defanged


def test_slack_escapes_model_text_angle_brackets() -> None:
    msg = render_slack(_content())
    text = str(msg["text"])
    assert "&lt;activity&gt;" in text  # rationale had <activity>
    assert "<activity>" not in text
    assert msg["mrkdwn"] is True


def test_slack_defangs_ips() -> None:
    text = str(render_slack(_content())["text"])
    assert "203[.]0[.]113[.]5" in text
    assert "203.0.113.5" not in text


def test_context_degraded_flag_rendered() -> None:
    text = render_telegram(_content(flags=("severity_floor", "context_degraded")))
    assert "context degraded" in text.lower()
