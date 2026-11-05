"""Proposal policy evaluation, analyst decisions, and approval history."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from backend.database import database_session
from backend.clock import utc_now_iso
from policy_engine.engine import PolicyEngine, PolicyResult


class ProposalNotFoundError(LookupError):
    pass


class ProposalDecisionConflict(RuntimeError):
    pass


class PolicyRejectedError(ValueError):
    def __init__(self, result: PolicyResult):
        super().__init__(result.reason)
        self.result = result


class ProposalReviewService:
    def __init__(self, database_path: str | Path, policy: PolicyEngine | None = None):
        self.database_path = Path(database_path)
        self.policy = policy or PolicyEngine()

    def _load(self, proposal_id: str) -> dict[str, Any]:
        with database_session(self.database_path) as connection:
            row = connection.execute(
                """SELECT p.proposal_id, p.investigation_id, p.finding_id, p.action_type,
                          p.parameters, p.rationale, p.policy_status, p.created_at,
                          f.event_id, f.severity, f.confidence, f.evidence_refs,
                          o.normalized_event, i.dataset_id
                   FROM response_proposals p
                   JOIN investigations i ON i.investigation_id=p.investigation_id
                   LEFT JOIN agent_findings f ON f.finding_id=p.finding_id
                   LEFT JOIN original_events o ON o.event_id=f.event_id
                   WHERE p.proposal_id=?""",
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise ProposalNotFoundError(proposal_id)
        item = dict(row)
        item["parameters"] = json.loads(item["parameters"])
        item["evidence_refs"] = json.loads(item["evidence_refs"] or "[]")
        item["evidence_event"] = json.loads(item["normalized_event"]) if item["normalized_event"] else {}
        return item

    def evaluate(self, proposal_id: str) -> dict[str, Any]:
        item = self._load(proposal_id)
        result = self._evaluate_item(item, item["action_type"], item["parameters"])
        with database_session(self.database_path) as connection:
            connection.execute(
                "UPDATE response_proposals SET policy_status=? WHERE proposal_id=? AND policy_status NOT IN ('approved','denied')",
                ("policy_validated" if result.allowed else "policy_rejected", proposal_id),
            )
            self._audit_policy_result(connection, item, result, "policy_engine")
        if item["policy_status"] not in {"approved", "denied"}:
            item["policy_status"] = "policy_validated" if result.allowed else "policy_rejected"
        return {"proposal": self._public(item), "policy": self._policy_payload(result)}

    def decide(
        self,
        proposal_id: str,
        *,
        reviewer: str,
        decision: str,
        comment: str = "",
        action_type: str | None = None,
        target_type: str | None = None,
        target_value: str | None = None,
    ) -> dict[str, Any]:
        reviewer = reviewer.strip()
        if not reviewer:
            raise ValueError("reviewer is required")
        if decision not in {"approved", "denied", "modified"}:
            raise ValueError("decision must be approved, denied, or modified")
        if decision == "modified" and all(value is None for value in (action_type, target_type, target_value)):
            raise ValueError("a modified decision must include at least one proposed change")
        if decision != "modified" and any(value is not None for value in (action_type, target_type, target_value)):
            raise ValueError("proposal changes are allowed only with a modified decision")
        item = self._load(proposal_id)
        if item["policy_status"] in {"approved", "denied"}:
            raise ProposalDecisionConflict("proposal already has a final decision")

        current_action = item["action_type"]
        current_parameters = item["parameters"]
        previous_parameters = dict(current_parameters)
        final_action = current_action
        final_parameters = dict(current_parameters)
        policy_result: PolicyResult | None = None
        if decision == "modified":
            if action_type is not None:
                final_action = action_type
            if target_type is not None:
                final_parameters["target_type"] = target_type
            if target_value is not None:
                final_parameters["target_value"] = target_value
            policy_result = self._evaluate_item(item, final_action, final_parameters)
            if not policy_result.allowed:
                self._record_policy_result(item, policy_result, reviewer)
                raise PolicyRejectedError(policy_result)
        elif decision == "approved":
            policy_result = self._evaluate_item(item, current_action, current_parameters)
            if not policy_result.allowed:
                self._record_policy_result(item, policy_result, reviewer)
                raise PolicyRejectedError(policy_result)

        approval_id = f"APR-{uuid.uuid4()}"
        decided_at = utc_now_iso(timespec="microseconds")
        modified = json.dumps(
            {
                "action_type": final_action,
                "parameters": final_parameters,
                "previous_action_type": current_action,
                "previous_parameters": previous_parameters,
            },
            sort_keys=True,
        ) if decision == "modified" else None
        next_status = "denied" if decision == "denied" else ("approved" if decision == "approved" else "policy_validated")
        try:
            with database_session(self.database_path) as connection:
                connection.execute(
                    """INSERT INTO approval_records
                       (approval_id, proposal_id, reviewer, decision, modified_parameters, comment, decided_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (approval_id, proposal_id, reviewer, decision, modified, comment.strip(), decided_at),
                )
                if decision == "modified":
                    connection.execute(
                        "UPDATE response_proposals SET action_type=?, parameters=?, policy_status=? WHERE proposal_id=?",
                        (final_action, json.dumps(final_parameters, sort_keys=True), next_status, proposal_id),
                    )
                else:
                    connection.execute(
                        "UPDATE response_proposals SET policy_status=? WHERE proposal_id=?",
                        (next_status, proposal_id),
                    )
                connection.execute(
                    """INSERT INTO feedback_records
                       (feedback_id, investigation_id, finding_id, proposal_id, analyst, decision, comment, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f"FDB-{uuid.uuid4()}", item["investigation_id"], item["finding_id"], proposal_id,
                        reviewer, decision, comment.strip(), decided_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO audit_logs
                       (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                       VALUES (?, ?, ?, 'response_proposal', ?, ?, ?, ?)""",
                    (
                        f"AUD-{approval_id}", reviewer, f"proposal.{decision}", proposal_id,
                        item["dataset_id"],
                        json.dumps({"approval_id": approval_id, "decision": decision, "comment": comment.strip(),
                                    "modified_parameters": json.loads(modified) if modified else None}, sort_keys=True),
                        decided_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            latest = self._load(proposal_id)
            if latest["policy_status"] in {"approved", "denied"}:
                raise ProposalDecisionConflict("proposal already has a final decision") from exc
            raise
        return {
            "approval_id": approval_id,
            "proposal_id": proposal_id,
            "reviewer": reviewer,
            "decision": decision,
            "proposal_status": next_status,
            "modified_parameters": json.loads(modified) if modified else None,
            "policy": self._policy_payload(policy_result) if policy_result else None,
            "decided_at": decided_at,
        }

    def history(self, proposal_id: str) -> list[dict[str, Any]]:
        self._load(proposal_id)
        with database_session(self.database_path) as connection:
            rows = connection.execute(
                """SELECT approval_id, proposal_id, reviewer, decision, modified_parameters, comment, decided_at
                   FROM approval_records WHERE proposal_id=? ORDER BY decided_at, approval_id""",
                (proposal_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if item["modified_parameters"]:
                item["modified_parameters"] = json.loads(item["modified_parameters"])
            result.append(item)
        return result

    def _evaluate_item(self, item: dict[str, Any], action: str, parameters: dict[str, Any]) -> PolicyResult:
        if not item["finding_id"] or not item["event_id"]:
            return PolicyResult(False, "missing_evidence", "Proposal has no linked finding or original event.")
        if item["event_id"] not in item["evidence_refs"]:
            return PolicyResult(False, "evidence_reference_mismatch", "Finding does not cite its linked original event.")
        return self.policy.evaluate(
            action_type=action,
            parameters=parameters,
            finding={"severity": item["severity"], "confidence": item["confidence"]},
            evidence_event=item["evidence_event"],
        )

    def _record_policy_result(self, item: dict[str, Any], result: PolicyResult, actor: str) -> None:
        with database_session(self.database_path) as connection:
            self._audit_policy_result(connection, item, result, actor)

    def _audit_policy_result(self, connection, item: dict[str, Any], result: PolicyResult, actor: str) -> None:
        occurred_at = utc_now_iso(timespec="microseconds")
        connection.execute(
            """INSERT INTO audit_logs
               (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
               VALUES (?, ?, ?, 'response_proposal', ?, ?, ?, ?)""",
            (
                f"AUD-POLICY-{uuid.uuid4()}",
                actor,
                "proposal.policy_validated" if result.allowed else "proposal.policy_rejected",
                item["proposal_id"],
                item["dataset_id"],
                json.dumps(self._policy_payload(result), sort_keys=True),
                occurred_at,
            ),
        )

    @staticmethod
    def _public(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item[key]
            for key in (
                "proposal_id", "investigation_id", "finding_id", "action_type", "parameters",
                "rationale", "policy_status", "created_at", "event_id", "severity", "confidence", "dataset_id",
            )
        }

    @staticmethod
    def _policy_payload(result: PolicyResult) -> dict[str, Any]:
        return {
            "allowed": result.allowed,
            "code": result.code,
            "reason": result.reason,
            "policy_version": result.policy_version,
        }
