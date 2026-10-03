"""Triage contracts: TriageModelOutput, TriageContext, TriageRecord."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class Classification(StrEnum):
    NOISE = "noise"
    INFORMATIONAL = "informational"
    ALERT = "alert"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_Action = Annotated[str, Field(min_length=1, max_length=200)]


class TriageModelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    classification: Classification
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    summary: Annotated[str, Field(max_length=200)]
    suggested_actions: Annotated[list[_Action], Field(max_length=10)]
    rationale: Annotated[str, Field(max_length=500)]


class TriageContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    src_ip_seen_before: bool
    related_events_24h: int
    distinct_rules_from_src_24h: int
    events_last_10min: int
    src_in_allowlist: bool
    finding_seen_before: bool
    matched_rule: str
    lookup_degraded: bool = False


class TriageRecord(BaseModel):
    alert_id: str
    event_id: str
    classification: Classification
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    severity: Severity
    summary: Annotated[str, Field(max_length=200)]
    incident_group_key: str
    context: TriageContext
    suggested_actions: Annotated[list[_Action], Field(max_length=10)]
    rationale: Annotated[str, Field(max_length=500)]
    triaged_at: datetime
