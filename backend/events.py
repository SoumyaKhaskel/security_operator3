"""Validated common security event models and UTC timestamp handling."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Severity = Literal["critical", "high", "medium", "low", "informational", "unknown"]


class SourceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str = "unknown"
    format: str = "unknown"
    origin: str = "imported"
    product: str | None = None


class EventDetails(BaseModel):
    model_config = ConfigDict(extra="allow")

    category: str = "unknown"
    type: str = "unknown"
    action: str | None = None
    outcome: str | None = None
    severity: Severity = "unknown"


class SecurityEvent(BaseModel):
    """Normalized event envelope. Extra source fields are preserved."""

    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.0"
    event_id: str = Field(min_length=1, max_length=256)
    dataset_id: str = Field(min_length=1, max_length=128)
    event_time: datetime
    ingested_at: datetime
    source: SourceInfo
    host: dict[str, Any] | None = None
    event: EventDetails
    actor: dict[str, Any] | None = None
    target: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    threat: dict[str, Any] | None = None
    message: str | None = None
    raw_event: dict[str, Any]
    labels: list[str] = Field(default_factory=list)
    status: str = "uninvestigated"

    @field_validator("event_time", "ingested_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(timezone.utc)
