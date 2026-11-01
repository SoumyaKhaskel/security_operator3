"""First, read-only threat investigation stage."""

from __future__ import annotations

import json
from pathlib import Path

from agents.event_view import ReadOnlyDatasetView
from agents.providers.base import AgentProvider
from agents.schemas import Finding, InvestigatorOutput


PROMPT_PATH = Path(__file__).parent / "prompts" / "v1" / "threat_investigator.txt"


class ThreatInvestigator:
    def __init__(self, provider: AgentProvider, page_size: int = 250):
        self.provider = provider
        self.page_size = page_size

    def run(self, event_view: ReadOnlyDatasetView) -> tuple[list[Finding], int]:
        prompt = PROMPT_PATH.read_text(encoding="utf-8")
        event_count = event_view.count_events()
        findings: list[Finding] = []
        seen: set[str] = set()
        for offset in range(0, event_count, self.page_size):
            events = event_view.list_events(limit=self.page_size, offset=offset)
            output = InvestigatorOutput.model_validate(
                self.provider.complete(
                    task="investigate",
                    system_prompt=prompt,
                    user_payload={
                        "events": events,
                        "untrusted_event_data": json.dumps(events, sort_keys=True),
                    },
                )
            )
            ids_in_page = {event["event_id"] for event in events}
            for finding in output.findings:
                if finding.event_id not in ids_in_page or not set(finding.evidence_refs) <= ids_in_page:
                    raise ValueError("Investigator finding cites evidence outside its selected dataset page")
                if finding.finding_id not in seen:
                    findings.append(finding)
                    seen.add(finding.finding_id)
        return findings, event_count
