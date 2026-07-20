"""UnifiedEvent contract — unified-event@1."""

import json
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

IPAddress = IPv4Address | IPv6Address


class UnifiedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Required
    event_id: str
    schema_version: Literal["unified-event@1"]
    timestamp: datetime
    source_module: str
    sensor: str
    source_alert_id: str
    event_type: str
    severity_hint: str
    summary: str  # 1–500 chars
    raw_ref: str

    # Optional typed
    src_ip: IPAddress | None = None
    dst_ip: IPAddress | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    signature: str | None = None
    rule_id: str | None = None
    username: str | None = None
    process: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    http_url: str | None = None
    http_user_agent: str | None = None
    dns_query: str | None = None
    mitre_technique_ids: list[str] | None = None
    fields: dict[str, Any] | None = None

    @field_validator("timestamp", mode="after")
    @classmethod
    def require_aware_and_normalize_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (UTC required)")
        return v.astimezone(UTC)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, v: str) -> str:
        if not 1 <= len(v) <= 500:
            raise ValueError("summary must be 1–500 characters")
        return v

    @field_validator("src_port", "dst_port")
    @classmethod
    def validate_port(cls, v: int | None) -> int | None:
        if v is not None and not 0 <= v <= 65535:
            raise ValueError("port must be in [0, 65535]")
        return v

    @model_validator(mode="after")
    def validate_fields_size(self) -> "UnifiedEvent":
        if self.fields is not None:
            size = len(json.dumps(self.fields).encode())
            if size > 4096:
                raise ValueError(f"fields exceeds 4096 bytes serialized ({size} bytes)")
        return self


def matched_rule_of(event: UnifiedEvent) -> str:
    return event.rule_id or event.signature or event.event_type
