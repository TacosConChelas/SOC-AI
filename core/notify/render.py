"""Per-channel rendering: defang IPs, escape model text, one reading order (§2.2)."""

from __future__ import annotations

from core.contracts.triage import Classification, Severity
from core.notify.content import NotificationContent
from core.notify.system import SystemNotification

_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "⚪",
}
_MARKER: dict[Classification, str] = {
    Classification.ALERT: "ALERT",
    Classification.INFORMATIONAL: "INFO",
    Classification.NOISE: "noise",
}


def _defang(text: str) -> str:
    return text.replace(".", "[.]")


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _yn(v: bool) -> str:
    return "sí" if v else "no"


def _lines(c: NotificationContent, *, escape: bool) -> list[str]:
    def m(text: str) -> str:
        return _slack_escape(text) if escape else text

    emoji = _EMOJI[c.severity]
    header = f"{emoji} {c.severity.upper()} · {_MARKER[c.classification]}   conf. {c.confidence:.2f}"
    flag_line = ""
    if c.flags:
        pretty = ", ".join(f.replace("_", " ") for f in c.flags)
        flag_line = f"⚑ {pretty}"
    # _defang applies only to structured IP fields (ADR-0004 §4) — never to free text from
    # the model (summary, rationale, suggested_actions), which would corrupt normal prose
    # like "10 min." into "10 min[.]".
    actions = "\n".join(f"{i}. {m(a)}" for i, a in enumerate(c.suggested_actions, 1))
    footer_src = _defang(c.src_ip) if c.src_ip else "—"
    footer_dst = _defang(c.dst_ip) if c.dst_ip else "—"
    lines = [
        header,
        flag_line,
        m(c.summary),
        "",
        f"Por qué: {m(c.rationale)}",
        "",
        "Evidencia (context):",
        f"· IP vista antes (30d): {_yn(c.src_ip_seen_before)}   · eventos 24h: {c.related_events_24h}",
        f"· reglas distintas 24h: {c.distinct_rules_from_src_24h}   · últimos 10 min: {c.events_last_10min}",
        f"· en allowlist: {_yn(c.src_in_allowlist)}",
        "",
        "Acciones sugeridas (NO ejecutadas):",
        actions,
        "",
        f"regla {c.matched_rule} · src {footer_src} → dst {footer_dst}",
        f"incidente {c.incident_group_key} · sensor {c.sensor}",
    ]
    return lines


def render_telegram(content: NotificationContent) -> str:
    return "\n".join(ln for ln in _lines(content, escape=False) if ln)


def render_slack(content: NotificationContent) -> dict[str, object]:
    return {"text": "\n".join(ln for ln in _lines(content, escape=True) if ln), "mrkdwn": True}


def _system_lines(n: SystemNotification, count: int) -> list[str]:
    if n.kind == "enrichment_degraded":
        header = f"⚑ enrichment degraded · sensor {n.sensor} · severity {n.severity.upper()}"
        body = "OpenSearch lookup failed — zeroed context enviado al modelo (in-distribution)."
    elif n.kind == "age_suppressed":
        header = f"⏳ age-suppressed · sensor {n.sensor} · severity {n.severity.upper()}"
        body = "Events older than notify_max_event_age were suppressed — still queryable in OpenSearch (ADR-0004 D-16)."
    else:
        header = f"⚠️ unclassified (system) · {n.reason} · sensor {n.sensor} · severity {n.severity.upper()}"
        detail_line = f"detail: {n.detail}" if n.detail else ""
        retries = f"retry_count: {n.retry_count}" if n.retry_count is not None else ""
        body = "   ".join(p for p in [detail_line, retries] if p)
    suffix = f"×{count} en la última ventana" if count > 1 else ""
    return [ln for ln in [header, body, suffix] if ln]


def render_telegram_system(notif: SystemNotification, count: int = 1) -> str:
    return "\n".join(_system_lines(notif, count))


def render_slack_system(notif: SystemNotification, count: int = 1) -> dict[str, object]:
    return {"text": "\n".join(_system_lines(notif, count)), "mrkdwn": True}
