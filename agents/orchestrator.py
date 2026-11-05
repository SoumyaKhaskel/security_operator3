"""Run and persist the three investigation agents in strict sequence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents.event_view import ReadOnlyDatasetView
from agents.providers.base import AgentProvider
from agents.response_planner import ResponsePlanner
from agents.schemas import HuntResult, InvestigationOutput
from agents.threat_hunter import ThreatHunter
from agents.threat_investigator import ThreatInvestigator
from backend.clock import utc_now_iso
from backend.database import database_session


class InvestigationNotFoundError(LookupError):
    """The requested investigation does not exist."""


class InvestigationStateError(RuntimeError):
    """The investigation cannot run in its current state."""


class InvestigationOrchestrator:
    def __init__(self, database_path: str | Path, provider: AgentProvider):
        self.database_path = Path(database_path)
        self.provider = provider

    def run(self, investigation_id: str) -> InvestigationOutput:
        with database_session(self.database_path) as connection:
            investigation = connection.execute(
                "SELECT investigation_id, dataset_id, requested_by, status FROM investigations WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
        if investigation is None:
            raise InvestigationNotFoundError(investigation_id)
        if investigation["status"] != "in_progress":
            raise InvestigationStateError("only a newly started investigation can run")
        dataset_id = investigation["dataset_id"]
        current_stage = "threat_investigator"
        self._set_status(investigation_id, "agent1_running")

        try:
            with ReadOnlyDatasetView(self.database_path, dataset_id) as event_view:
                # Stage 1: inspect only the original-event view bound to this investigation's dataset.
                findings, scanned_count = ThreatInvestigator(self.provider).run(event_view)
                findings = [
                    finding.model_copy(update={"finding_id": f"{investigation_id}-{finding.finding_id}"})
                    for finding in findings
                ]
                self._persist_findings(investigation_id, findings)

                # Stage 2: each hunting search is executed by the app with the same pinned read-only view.
                current_stage = "threat_hunter"
                self._set_status(investigation_id, "agent2_running")
                hunts, hunt_summary = ThreatHunter(self.provider).run(event_view, findings)
                hunts = [
                    hunt.model_copy(
                        update={
                            "query": hunt.query.model_copy(
                                update={"query_id": f"{investigation_id}-{hunt.query.query_id}"}
                            )
                        }
                    )
                    for hunt in hunts
                ]
                self._persist_hunts(investigation_id, hunts)

                # Stage 3: produce reviewable proposal records; this stage cannot execute actions.
                current_stage = "response_planner"
                self._set_status(investigation_id, "agent3_running")
                proposals = ResponsePlanner(self.provider).run(event_view, findings, hunts)
                self._persist_proposals(investigation_id, proposals)

            summary = {
                "scanned_event_count": scanned_count,
                "finding_count": len(findings),
                "hunt_count": len(hunts),
                "proposal_count": len(proposals),
                "hunt_summary": hunt_summary,
            }
            completed_at = utc_now_iso()
            with database_session(self.database_path) as connection:
                connection.execute(
                    "UPDATE investigations SET status='completed', completed_at=?, summary=? WHERE investigation_id=?",
                    (completed_at, json.dumps(summary, sort_keys=True), investigation_id),
                )
                connection.execute(
                    """INSERT INTO audit_logs
                       (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                       VALUES (?, ?, 'investigation.completed', 'investigation', ?, ?, ?, ?)""",
                    (
                        f"AUD-{investigation_id}",
                        investigation["requested_by"],
                        investigation_id,
                        dataset_id,
                        json.dumps(summary, sort_keys=True),
                        completed_at,
                    ),
                )
            return InvestigationOutput(
                investigation_id=investigation_id,
                dataset_id=dataset_id,
                status="completed",
                scanned_event_count=scanned_count,
                findings=findings,
                hunts=hunts,
                proposals=proposals,
            )
        except Exception as exc:
            with database_session(self.database_path) as connection:
                connection.execute(
                    "UPDATE investigations SET status='failed', completed_at=?, summary=? WHERE investigation_id=?",
                    (utc_now_iso(), json.dumps({"failed_stage": current_stage, "error": str(exc)[:1000]}), investigation_id),
                )
                connection.execute(
                    """INSERT INTO audit_logs
                       (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                       VALUES (?, ?, 'investigation.failed', 'investigation', ?, ?, ?, ?)""",
                    (
                        f"AUD-{investigation_id}-FAILED", investigation["requested_by"], investigation_id,
                        dataset_id, json.dumps({"failed_stage": current_stage, "error": str(exc)[:1000]}), utc_now_iso(),
                    ),
                )
            raise

    def _persist_findings(self, investigation_id: str, findings: list) -> None:
        with database_session(self.database_path) as connection:
            for finding in findings:
                connection.execute(
                    """INSERT INTO agent_findings
                       (finding_id, investigation_id, event_id, agent_name, severity, confidence,
                        title, explanation, evidence_refs, created_at)
                       VALUES (?, ?, ?, 'threat_investigator', ?, ?, ?, ?, ?, ?)""",
                    (
                        finding.finding_id,
                        investigation_id,
                        finding.event_id,
                        finding.severity,
                        finding.confidence,
                        finding.title,
                        finding.explanation,
                        json.dumps(finding.evidence_refs),
                        utc_now_iso(),
                    ),
                )

    def _persist_hunts(self, investigation_id: str, hunts: list[HuntResult]) -> None:
        with database_session(self.database_path) as connection:
            for hunt in hunts:
                connection.execute(
                    """INSERT INTO hunting_queries(query_id, investigation_id, query_text, result_count, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        hunt.query.query_id,
                        investigation_id,
                        json.dumps(hunt.query.model_dump(mode="json"), sort_keys=True),
                        len(hunt.matched_event_ids),
                        utc_now_iso(),
                    ),
                )

    def _persist_proposals(self, investigation_id: str, proposals: list) -> None:
        with database_session(self.database_path) as connection:
            for proposal in proposals:
                connection.execute(
                    """INSERT INTO response_proposals
                       (proposal_id, investigation_id, finding_id, action_type, parameters, rationale,
                        policy_status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'pending_validation', ?)""",
                    (
                        proposal.proposal_id,
                        investigation_id,
                        proposal.finding_id,
                        proposal.action_type,
                        json.dumps(
                            {"target_type": proposal.target_type, "target_value": proposal.target_value},
                            sort_keys=True,
                        ),
                        proposal.rationale,
                        utc_now_iso(),
                    ),
                )

    def _set_status(self, investigation_id: str, status: str) -> None:
        with database_session(self.database_path) as connection:
            investigation = connection.execute(
                "SELECT requested_by, dataset_id FROM investigations WHERE investigation_id=?", (investigation_id,)
            ).fetchone()
            connection.execute(
                "UPDATE investigations SET status=? WHERE investigation_id=?",
                (status, investigation_id),
            )
            if investigation:
                connection.execute(
                    """INSERT INTO audit_logs
                       (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                       VALUES (?, ?, 'agent.stage_started', 'investigation', ?, ?, ?, ?)""",
                    (
                        f"AUD-{investigation_id}-{status}", investigation["requested_by"], investigation_id,
                        investigation["dataset_id"], json.dumps({"status": status}), utc_now_iso(),
                    ),
                )
