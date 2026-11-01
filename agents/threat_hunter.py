"""Second stage: structured, dataset-pinned, bounded event searches."""

from __future__ import annotations

from pathlib import Path

from agents.event_view import ReadOnlyDatasetView
from agents.providers.base import AgentProvider
from agents.schemas import Finding, HuntResult, HunterOutput


PROMPT_PATH = Path(__file__).parent / "prompts" / "v1" / "threat_hunter.txt"


class ThreatHunter:
    def __init__(self, provider: AgentProvider):
        self.provider = provider

    def run(self, event_view: ReadOnlyDatasetView, findings: list[Finding]) -> tuple[list[HuntResult], str]:
        evidence_by_id = {}
        for finding in findings:
            matches = event_view.search_events(needle=finding.event_id, limit=1)
            if matches:
                evidence_by_id[finding.event_id] = matches[0]
        output = HunterOutput.model_validate(
            self.provider.complete(
                task="hunt",
                system_prompt=PROMPT_PATH.read_text(encoding="utf-8"),
                user_payload={
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                    "evidence_by_id": evidence_by_id,
                },
            )
        )
        results = []
        for query in output.queries:
            matches = event_view.search_events(
                category=query.category,
                severity=query.severity,
                needle=query.needle,
                limit=100,
            )
            results.append(HuntResult(query=query, matched_event_ids=[item["event_id"] for item in matches]))
        return results, output.summary
