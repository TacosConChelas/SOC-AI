"""DeadLetterRecord contract."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field


class DeadLetterReason(StrEnum):
    PARSE_FAILURE = "parse_failure"
    MODEL_UNAVAILABLE = "model_unavailable"


class DeadLetterRecord(BaseModel):
    alert_id: str
    event_id: str
    source_module: str
    sensor: str
    severity: str
    reason: DeadLetterReason
    retry_count: int
    dead_lettered_at: datetime
    detail: Annotated[str, Field(min_length=1, max_length=500)]
