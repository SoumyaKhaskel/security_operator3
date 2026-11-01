"""Strict schemas for agent findings, hunts, and response proposals."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(StrictOutput):
    finding_id: str
    event_id: str
    severity: Literal["critical", "high", "medium", "low", "informational", "unknown"]
    confidence: float = Field(ge=0, le=1)
    title: str = Field(min_length=1, max_length=160)
    explanation: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class InvestigatorOutput(StrictOutput):
    findings: list[Finding] = Field(max_length=500)


class HuntRequest(StrictOutput):
    query_id: str
    category: str | None = Field(default=None, max_length=100)
    severity: Literal["critical", "high", "medium", "low", "informational", "unknown"] | None = None
    needle: str | None = Field(default=None, max_length=160)


class HunterOutput(StrictOutput):
    queries: list[HuntRequest] = Field(max_length=100)
    summary: str = Field(max_length=2000)


class HuntResult(StrictOutput):
    query: HuntRequest
    matched_event_ids: list[str] = Field(max_length=100)


class ResponseProposal(StrictOutput):
    proposal_id: str
    finding_id: str
    action_type: Literal["isolate_host", "disable_account", "block_ip", "monitor"]
    target_type: Literal["host", "account", "ip"]
    target_value: str = Field(min_length=1, max_length=256)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class PlannerOutput(StrictOutput):
    proposals: list[ResponseProposal] = Field(max_length=100)


class InvestigationOutput(StrictOutput):
    investigation_id: str
    dataset_id: str
    status: Literal["completed"]
    scanned_event_count: int = Field(ge=0)
    findings: list[Finding]
    hunts: list[HuntResult]
    proposals: list[ResponseProposal]
