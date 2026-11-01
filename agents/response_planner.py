"""Third stage: evidence-backed proposals only; no action execution."""

from __future__ import annotations

from pathlib import Path

from agents.event_view import ReadOnlyDatasetView
from agents.providers.base import AgentProvider
from agents.schemas import Finding, HuntResult, PlannerOutput, ResponseProposal


PROMPT_PATH = Path(__file__).parent / "prompts" / "v1" / "response_planner.txt"


class ResponsePlanner:
    def __init__(self, provider: AgentProvider):
        self.provider = provider

    def run(
        self,
        event_view: ReadOnlyDatasetView,
        findings: list[Finding],
        hunts: list[HuntResult],
    ) -> list[ResponseProposal]:
        evidence_ids = {finding.event_id for finding in findings}
        evidence_ids.update(event_id for hunt in hunts for event_id in hunt.matched_event_ids)
        evidence_by_id = {}
        for event_id in evidence_ids:
            matches = event_view.search_events(needle=event_id, limit=1)
            if matches:
                evidence_by_id[event_id] = matches[0]
        output = PlannerOutput.model_validate(
            self.provider.complete(
                task="plan_response",
                system_prompt=PROMPT_PATH.read_text(encoding="utf-8"),
                user_payload={
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                    "hunts": [hunt.model_dump(mode="json") for hunt in hunts],
                    "evidence_by_id": evidence_by_id,
                },
            )
        )
        findings_by_id = {finding.finding_id: finding for finding in findings}
        allowed_evidence = set(evidence_by_id)
        for proposal in output.proposals:
            finding = findings_by_id.get(proposal.finding_id)
            if finding is None or proposal.evidence_refs[0] != finding.event_id:
                raise ValueError("Response proposal must reference its own validated finding")
            if not set(proposal.evidence_refs) <= allowed_evidence:
                raise ValueError("Response proposal cites evidence outside the selected dataset")
            if not self._target_is_evidenced(proposal, evidence_by_id):
                raise ValueError("Response proposal target is not present in cited event evidence")
        return output.proposals

    @staticmethod
    def _target_is_evidenced(proposal: ResponseProposal, evidence_by_id: dict) -> bool:
        for event_id in proposal.evidence_refs:
            event = evidence_by_id.get(event_id, {})
            host = event.get("host", {}) if isinstance(event.get("host"), dict) else {}
            if proposal.target_type == "host" and host.get("hostname") == proposal.target_value:
                return True
            actor = event.get("actor", {}) if isinstance(event.get("actor"), dict) else {}
            network = event.get("network", {}) if isinstance(event.get("network"), dict) else {}
            if proposal.target_type == "account" and actor.get("username") == proposal.target_value:
                return True
            if proposal.target_type == "ip" and proposal.target_value in {
                actor.get("ip"), network.get("source_ip")
            }:
                return True
        return False
