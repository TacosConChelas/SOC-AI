"""Wazuh alert normalizer → UnifiedEvent (unified-event@1).

One normalizer per tool — the model always sees a single format.
Mitre IDs come only from rule.mitre.id; Suricata-sourced alerts (rule 86601)
produce mitre_technique_ids=[] because ET Open signatures carry no mitre block.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.contracts.event import UnifiedEvent


def _severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _event_type(rule: dict[str, Any]) -> str:
    groups: list[str] = rule.get("groups", [])
    if "ids" in groups or "suricata" in groups:
        return "NIDS"
    if "syscheck" in groups or "fim" in groups:
        return "FIM"
    if "authentication" in groups or "sshd" in groups or "win_authentication" in groups:
        return "HIDS"
    return "SIEM"


def _clean_ip(raw: Any) -> str | None:
    if not raw or str(raw).lower() in {"unknown", "none", ""}:
        return None
    return str(raw)


def _clean_port(raw: Any) -> int | None:
    try:
        val = int(raw)
        return val if 0 <= val <= 65535 else None
    except (TypeError, ValueError):
        return None


def normalize(alert: dict[str, Any]) -> UnifiedEvent:
    """Convert a raw Wazuh alert dict to UnifiedEvent.

    Raises ValueError if required fields are missing or malformed.
    Never embeds raw log content — payload goes to OpenSearch; raw_ref is the pointer.
    """
    rule: dict[str, Any] = alert.get("rule") or {}
    agent: dict[str, Any] = alert.get("agent") or {}
    data: dict[str, Any] = alert.get("data") or {}

    alert_id = str(alert["id"])
    timestamp_raw: str = alert["timestamp"]
    # Wazuh timestamps: "2026-07-20T12:00:00.000+0000" or "...Z"
    timestamp = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))

    level = int(rule.get("level", 0))
    description: str = (rule.get("description") or "Wazuh alert")[:500]
    sensor: str = agent.get("name") or "unknown"
    rule_id_raw = rule.get("id")

    mitre_raw = rule.get("mitre", {}).get("id")
    mitre_ids: list[str] | None = mitre_raw if isinstance(mitre_raw, list) else None

    return UnifiedEvent(
        event_id=alert_id,
        schema_version="unified-event@1",
        timestamp=timestamp,
        source_module="wazuh",
        sensor=sensor,
        source_alert_id=alert_id,
        event_type=_event_type(rule),
        severity_hint=_severity_from_level(level),
        summary=description,
        raw_ref=f"opensearch://wazuh-alerts-*/{alert_id}",
        src_ip=_clean_ip(data.get("srcip")),
        dst_ip=_clean_ip(data.get("dstip")),
        src_port=_clean_port(data.get("srcport")),
        dst_port=_clean_port(data.get("dstport")),
        protocol=data.get("protocol") or None,
        rule_id=str(rule_id_raw) if rule_id_raw is not None else None,
        mitre_technique_ids=mitre_ids,
    )
