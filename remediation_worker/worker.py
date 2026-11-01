"""Execute approved proposals in simulation mode and preserve evidence snapshots."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.database import database_session
from policy_engine.review import PolicyRejectedError, ProposalNotFoundError, ProposalReviewService


class ExecutionNotAuthorized(PermissionError):
    """The proposal lacks an active human approval or valid policy result."""


class ExecutionConflict(RuntimeError):
    """An idempotency key or approval already has a different execution."""


class ExecutionNotFoundError(LookupError):
    """The requested simulation execution does not exist."""


class SimulationRemediationWorker:
    def __init__(self, database_path: str | Path, review_service: ProposalReviewService | None = None):
        self.database_path = Path(database_path)
        self.review_service = review_service or ProposalReviewService(database_path)

    def execute(self, proposal_id: str, approval_id: str, idempotency_key: str) -> dict[str, Any]:
        key = idempotency_key.strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key):
            raise ValueError("Idempotency-Key must be 1-128 letters, digits, periods, underscores, colons, or hyphens")
        existing = self._by_idempotency_key(key)
        if existing:
            if existing["proposal_id"] == proposal_id and existing["approval_id"] == approval_id:
                return existing
            raise ExecutionConflict("Idempotency-Key was already used for a different execution")

        existing_approval = self._by_approval(proposal_id, approval_id)
        if existing_approval:
            raise ExecutionConflict("This approval already has a simulation execution")

        try:
            policy = self.review_service.evaluate(proposal_id)["policy"]
        except ProposalNotFoundError as exc:
            raise ExecutionNotAuthorized("proposal does not exist") from exc
        if not policy["allowed"]:
            raise ExecutionNotAuthorized(f"current proposal fails policy: {policy['code']}")

        proposal = self._load_authorized_proposal(proposal_id, approval_id)
        if proposal is None:
            raise ExecutionNotAuthorized("execution requires the final approved decision for this proposal")
        if proposal["policy_status"] != "approved":
            raise ExecutionNotAuthorized("proposal is not in the approved state")

        execution_id = f"EXEC-{uuid.uuid4()}"
        started_at = self._now()
        completed_at = self._now()
        before_event = proposal["original_event"]
        after_event = dict(before_event)
        after_event["status"] = "resolved"
        after_event["simulation"] = {
            "execution_id": execution_id,
            "proposal_id": proposal_id,
            "approval_id": approval_id,
            "action_type": proposal["action_type"],
            "parameters": proposal["parameters"],
            "mode": "simulation",
        }
        outcome = {
            "result": "simulated_success",
            "action_type": proposal["action_type"],
            "parameters": proposal["parameters"],
            "original_event_unchanged": True,
        }
        processed_event_id = f"PROC-{uuid.uuid4()}"

        try:
            with database_session(self.database_path) as connection:
                connection.execute(
                    """INSERT INTO execution_records
                       (execution_id, proposal_id, approval_id, mode, idempotency_key, status, outcome,
                        started_at, completed_at)
                       VALUES (?, ?, ?, 'simulation', ?, 'simulated_success', ?, ?, ?)""",
                    (
                        execution_id, proposal_id, approval_id, key,
                        json.dumps(outcome, sort_keys=True), started_at, completed_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO processed_events
                       (processed_event_id, original_event_id, investigation_id, finding_id, execution_id,
                        status, before_state, after_state, created_at)
                       VALUES (?, ?, ?, ?, ?, 'simulated_execution_successful', ?, ?, ?)""",
                    (
                        processed_event_id, proposal["event_id"], proposal["investigation_id"],
                        proposal["finding_id"], execution_id,
                        json.dumps(before_event, sort_keys=True),
                        json.dumps(after_event, sort_keys=True), completed_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO feedback_records
                       (feedback_id, investigation_id, finding_id, proposal_id, analyst, decision, comment, created_at)
                       VALUES (?, ?, ?, ?, ?, 'simulated_execution_successful', ?, ?)""",
                    (
                        f"FDB-{uuid.uuid4()}", proposal["investigation_id"], proposal["finding_id"],
                        proposal_id, proposal["reviewer"], f"Simulation execution {execution_id}", completed_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO audit_logs
                       (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                       VALUES (?, ?, 'execution.simulated_success', 'execution', ?, ?, ?, ?)""",
                    (
                        f"AUD-{execution_id}", proposal["reviewer"], execution_id, proposal["dataset_id"],
                        json.dumps({"proposal_id": proposal_id, "approval_id": approval_id, "mode": "simulation"}, sort_keys=True),
                        completed_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            retry = self._by_idempotency_key(key)
            if retry and retry["proposal_id"] == proposal_id and retry["approval_id"] == approval_id:
                return retry
            if self._by_approval(proposal_id, approval_id):
                raise ExecutionConflict("This approval already has a simulation execution") from exc
            raise
        return self.get_execution(execution_id)

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        with database_session(self.database_path) as connection:
            row = connection.execute(
                """SELECT execution_id, proposal_id, approval_id, mode, idempotency_key, status,
                          outcome, started_at, completed_at
                   FROM execution_records WHERE execution_id=?""",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise ExecutionNotFoundError(execution_id)
        result = dict(row)
        result["outcome"] = json.loads(result["outcome"])
        return result

    def comparison(self, execution_id: str) -> dict[str, Any]:
        execution = self.get_execution(execution_id)
        with database_session(self.database_path) as connection:
            row = connection.execute(
                """SELECT original_event_id, investigation_id, finding_id, status, before_state,
                          after_state, created_at
                   FROM processed_events WHERE execution_id=?""",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise ExecutionNotFoundError(execution_id)
        record = dict(row)
        record["before_state"] = json.loads(record["before_state"])
        record["after_state"] = json.loads(record["after_state"])
        return {"execution": execution, "comparison": record}

    def _load_authorized_proposal(self, proposal_id: str, approval_id: str) -> dict[str, Any] | None:
        with database_session(self.database_path) as connection:
            row = connection.execute(
                """SELECT p.proposal_id, p.investigation_id, p.finding_id, p.action_type,
                          p.parameters, p.policy_status, a.approval_id, a.reviewer,
                          i.dataset_id, f.event_id, o.normalized_event
                   FROM response_proposals p
                   JOIN investigations i ON i.investigation_id=p.investigation_id
                   JOIN agent_findings f ON f.finding_id=p.finding_id
                   JOIN original_events o ON o.event_id=f.event_id AND o.dataset_id=i.dataset_id
                   JOIN approval_records a ON a.proposal_id=p.proposal_id
                   WHERE p.proposal_id=? AND a.approval_id=? AND a.decision='approved'""",
                (proposal_id, approval_id),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["parameters"] = json.loads(result["parameters"])
        result["original_event"] = json.loads(result.pop("normalized_event"))
        return result

    def _by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with database_session(self.database_path) as connection:
            row = connection.execute(
                "SELECT execution_id, proposal_id, approval_id FROM execution_records WHERE idempotency_key=?",
                (key,),
            ).fetchone()
        return self.get_execution(row["execution_id"]) if row else None

    def _by_approval(self, proposal_id: str, approval_id: str) -> dict[str, Any] | None:
        with database_session(self.database_path) as connection:
            row = connection.execute(
                "SELECT execution_id FROM execution_records WHERE proposal_id=? AND approval_id=?",
                (proposal_id, approval_id),
            ).fetchone()
        return self.get_execution(row["execution_id"]) if row else None

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
