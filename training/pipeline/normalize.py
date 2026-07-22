"""Convert raw alert rows (Kaggle CSV / manual JSONL) to UnifiedEvent + TriageContext.

Intermediate dict contract (used by from_kaggle_row and manual examples):
    Required keys — any UnifiedEvent required field by name, plus:
        summary        str  ≤500 chars
        event_type     str  e.g. "NIDS", "syscheck", "GENERIC"
        severity_hint  str  "low" | "medium" | "high" | "critical"
    Optional keys — any UnifiedEvent optional field by name, plus:
        ctx_src_ip_seen_before          bool  (default False)
        ctx_related_events_24h          int   (default 0)
        ctx_distinct_rules_from_src_24h int   (default 0)
        ctx_events_last_10min           int   (default 0)
        ctx_src_in_allowlist            bool  (default False)
        ctx_matched_rule                str   (falls back to rule_id/signature/event_type)
        ctx_lookup_degraded             bool  (default True when ctx_* keys absent)
    Label key (carried through, not consumed here):
        native_label   str  original dataset label string

Kaggle expected columns (from_kaggle_row remaps these — adjust for actual CSV):
    EventID | Timestamp | SourceIP | DestinationIP | SourcePort | DestinationPort
    Protocol | AlertType | Severity | Description | Label
"""

from __future__ import annotations

import csv
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from core.contracts.event import UnifiedEvent
from core.contracts.triage import TriageContext

Row = dict[str, object]

# ─── typed field helpers ─────────────────────────────────────────────────────


def _str(row: Row, *keys: str, default: str = "") -> str:
    for k in keys:
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
        if v is not None and v != "":
            return str(v)
    return default


def _int(row: Row, *keys: str, default: int = 0) -> int:
    for k in keys:
        v = row.get(k)
        if v is None or v == "":
            continue
        if isinstance(v, int):
            return v
        try:
            return int(str(v))
        except (ValueError, TypeError):
            continue
    return default


def _bool(row: Row, *keys: str, default: bool = False) -> bool:
    for k in keys:
        v = row.get(k)
        if v is None:
            continue
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
        return bool(v)
    return default


def _opt_str(row: Row, *keys: str) -> str | None:
    for k in keys:
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
        if v is not None and v != "":
            return str(v)
    return None


def _opt_int(row: Row, *keys: str) -> int | None:
    for k in keys:
        v = row.get(k)
        if v is None or v == "":
            continue
        if isinstance(v, int):
            return v
        try:
            return int(str(v))
        except (ValueError, TypeError):
            continue
    return None


def _has_context(row: Row) -> bool:
    return any(k.startswith("ctx_") for k in row)


def _parse_ts(row: Row, *keys: str) -> datetime:
    for k in keys:
        v = row.get(k)
        if isinstance(v, datetime):
            return v if v.tzinfo is not None else v.replace(tzinfo=UTC)
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=UTC)
        if isinstance(v, str) and v:
            try:
                dt = datetime.fromisoformat(v)
                return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
            except ValueError:
                pass
    return datetime.now(UTC)


# ─── core normalizer ─────────────────────────────────────────────────────────


def normalize_raw(row: Row) -> tuple[UnifiedEvent, TriageContext]:
    """Convert an intermediate-format dict to (UnifiedEvent, TriageContext).

    Context keys are optional; absence means lookup_degraded=True and zeroed counts.
    """
    matched_rule = _str(row, "ctx_matched_rule", "rule_id", "signature", "event_type", default="unknown")
    ctx = TriageContext(
        src_ip_seen_before=_bool(row, "ctx_src_ip_seen_before"),
        related_events_24h=_int(row, "ctx_related_events_24h"),
        distinct_rules_from_src_24h=_int(row, "ctx_distinct_rules_from_src_24h"),
        events_last_10min=_int(row, "ctx_events_last_10min"),
        src_in_allowlist=_bool(row, "ctx_src_in_allowlist"),
        matched_rule=matched_rule,
        lookup_degraded=_bool(row, "ctx_lookup_degraded", default=not _has_context(row)),
    )

    summary_raw = _str(row, "summary", "description", "notes", default="Alert")
    event = UnifiedEvent(
        event_id=_str(row, "event_id", "eventid", "id", default=str(uuid.uuid4())),
        schema_version="unified-event@1",
        timestamp=_parse_ts(row, "timestamp", "datetime", "time"),
        source_module=_str(row, "source_module", default="dataset"),
        sensor=_str(row, "sensor", default="dataset"),
        source_alert_id=_str(row, "source_alert_id", "event_id", "eventid", "id", default=str(uuid.uuid4())),
        event_type=_str(row, "event_type", "alerttype", "alert_type", "category", default="GENERIC"),
        severity_hint=_str(row, "severity_hint", "severity", default="low").lower(),
        summary=summary_raw[:500],
        raw_ref=_str(row, "raw_ref", default=f"dataset://{row.get('event_id', 'unknown')}"),
        src_ip=_opt_str(row, "src_ip", "sourceip", "source_ip"),
        dst_ip=_opt_str(row, "dst_ip", "destinationip", "destination_ip"),
        src_port=_opt_int(row, "src_port", "sourceport", "source_port"),
        dst_port=_opt_int(row, "dst_port", "destinationport", "destination_port"),
        protocol=_opt_str(row, "protocol"),
        signature=_opt_str(row, "signature"),
        rule_id=_opt_str(row, "rule_id", "ruleid"),
        username=_opt_str(row, "username"),
        process=_opt_str(row, "process"),
        file_path=_opt_str(row, "file_path", "filepath"),
        file_hash=_opt_str(row, "file_hash", "filehash", "md5", "sha256"),
        http_url=_opt_str(row, "http_url"),
        http_user_agent=_opt_str(row, "http_user_agent", "useragent"),
        dns_query=_opt_str(row, "dns_query"),
        mitre_technique_ids=(
            row.get("mitre_technique_ids") if isinstance(row.get("mitre_technique_ids"), list) else None
        ),
    )
    return event, ctx


# ─── Kaggle CSV mapper ────────────────────────────────────────────────────────


def from_kaggle_row(row: dict[str, str]) -> Row:
    """Remap Kaggle SOC dataset CSV columns to the intermediate format.

    Expected Kaggle columns (case-insensitive after .lower().strip()):
        eventid, timestamp, sourceip, destinationip, sourceport, destinationport,
        protocol, alerttype, severity, description, label

    Adjust this mapping if the actual CSV uses different names.
    """
    r: Row = {k.lower().strip().replace(" ", "_"): v for k, v in row.items()}

    sev_raw = _str(r, "severity", "rule_level", default="low").lower()
    if sev_raw in ("1", "2", "3"):
        sev_raw = "low"
    elif sev_raw in ("4", "5", "6", "7"):
        sev_raw = "medium"
    elif sev_raw in ("8", "9", "10", "11"):
        sev_raw = "high"
    elif sev_raw in ("12", "13", "14", "15"):
        sev_raw = "critical"

    return {
        "event_id": _str(r, "eventid", "event_id", "id", default=str(uuid.uuid4())),
        "timestamp": _opt_str(r, "timestamp", "datetime", "time", "date"),
        "source_module": "kaggle",
        "sensor": _str(r, "sensor", "hostname", "device", default="kaggle-dataset"),
        "source_alert_id": _str(r, "eventid", "event_id", "id", default=str(uuid.uuid4())),
        "event_type": "NIDS" if _opt_str(r, "sourceip", "src_ip") else "HOST",
        "severity_hint": sev_raw,
        "summary": _str(r, "description", "summary", "notes", "alerttype", default="Alert")[:500],
        "raw_ref": f"kaggle://soc-dataset/{_str(r, 'eventid', 'event_id', default='unknown')}",
        "src_ip": _opt_str(r, "sourceip", "src_ip", "source_ip"),
        "dst_ip": _opt_str(r, "destinationip", "dst_ip", "destination_ip"),
        "src_port": _opt_str(r, "sourceport", "src_port", "source_port"),
        "dst_port": _opt_str(r, "destinationport", "dst_port", "destination_port"),
        "protocol": _opt_str(r, "protocol"),
        "signature": _opt_str(r, "alerttype", "alert_type", "signature", "category", "rule"),
        "native_label": _opt_str(r, "label", "classification", "category", "ground_truth"),
    }


# ─── file-level iterators ────────────────────────────────────────────────────


def from_csv(
    path: str | Path,
    source: str = "kaggle",
) -> Iterator[tuple[UnifiedEvent, TriageContext, str | None]]:
    """Yield (event, context, native_label) for each row in a CSV.

    source="kaggle" applies from_kaggle_row(); source="raw" passes the row directly.
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if source == "kaggle":
                intermediate: Row = from_kaggle_row(row)
            else:
                intermediate = {k: v for k, v in row.items()}
            native_label = str(intermediate.pop("native_label", "") or "")
            try:
                event, ctx = normalize_raw(intermediate)
            except Exception:
                continue
            yield event, ctx, native_label or None


def from_jsonl(
    path: str | Path,
) -> Iterator[tuple[UnifiedEvent, TriageContext, str | None]]:
    """Yield (event, context, native_label) for each line in a JSONL file.

    Expects the same intermediate dict format (owner-written manual examples).
    """
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row: Row = json.loads(line)
            native_label = str(row.pop("native_label", "") or "")
            try:
                event, ctx = normalize_raw(row)
            except Exception:
                continue
            yield event, ctx, native_label or None
