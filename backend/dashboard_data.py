"""Read-only dashboard projections built from operational database state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.config import Settings
from backend.database import database_session
from backend.services.datasets import DatasetService


class DashboardDataService:
    def __init__(self, database_path: str | Path, datasets: DatasetService, settings: Settings):
        self.database_path = Path(database_path)
        self.datasets = datasets
        self.settings = settings

    def overview(self, dataset_id: str | None = None) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        where, args = self._dataset_where(dataset_id, "dataset_id")
        with database_session(self.database_path) as connection:
            total = connection.execute(f"SELECT count(*) FROM original_events WHERE {where}", args).fetchone()[0]
            critical_high = connection.execute(
                f"SELECT count(*) FROM original_events WHERE {where} AND severity IN ('critical','high')", args
            ).fetchone()[0]
            severity = self._group_counts(connection, "original_events", "severity", where, args)
            categories = self._group_counts(connection, "original_events", "category", where, args)
            provenance = self._group_counts(connection, "original_events", "provenance", where, args)
            investigations = self._investigation_counts(connection, dataset_id)
            finding_where, finding_args = self._dataset_where(dataset_id, "i.dataset_id")
            finding_total = connection.execute(
                f"""SELECT count(*) FROM agent_findings f JOIN investigations i
                    ON i.investigation_id=f.investigation_id WHERE {finding_where}""",
                finding_args,
            ).fetchone()[0]
            proposal_where = "i.dataset_id = ?" if dataset_id else "1=1"
            proposal_args = [dataset_id] if dataset_id else []
            pending_approvals = connection.execute(
                f"""SELECT count(*) FROM response_proposals p
                    JOIN investigations i ON i.investigation_id=p.investigation_id
                    WHERE {proposal_where} AND p.policy_status NOT IN ('approved','denied')""",
                proposal_args,
            ).fetchone()[0]
            activity = [
                {"period": row[0], "count": row[1]}
                for row in connection.execute(
                    f"""SELECT substr(event_time,1,13) AS period, count(*)
                        FROM original_events WHERE {where}
                        GROUP BY period ORDER BY period DESC LIMIT 48""",
                    args,
                ).fetchall()[::-1]
            ]
            recent = self._recent_investigations(connection, dataset_id, 8)
            findings = self._recent_findings(connection, dataset_id, 8)
        return {
            "dataset_id": dataset_id,
            "total_events": total,
            "critical_high_events": critical_high,
            "investigations": investigations,
            "pending_approvals": pending_approvals,
            "severity_distribution": severity,
            "category_distribution": categories,
            "provenance_distribution": provenance,
            "total_findings": finding_total,
            "event_activity": activity,
            "recent_investigations": recent,
            "recent_findings": findings,
        }

    def dataset_detail(self, dataset_id: str) -> dict[str, Any]:
        manifest = self.datasets.require_dataset(dataset_id)
        with database_session(self.database_path) as connection:
            row = connection.execute(
                "SELECT event_count, created_at, status FROM datasets WHERE dataset_id=?", (dataset_id,)
            ).fetchone()
            severity = self._group_counts(connection, "original_events", "severity", "dataset_id = ?", [dataset_id])
            categories = self._group_counts(connection, "original_events", "category", "dataset_id = ?", [dataset_id])
            batch = connection.execute(
                """SELECT status, completed_at, accepted_count, rejected_count, source_name
                   FROM ingestion_batches WHERE dataset_id=? ORDER BY started_at DESC LIMIT 1""",
                (dataset_id,),
            ).fetchone()
        return {
            "dataset_id": dataset_id,
            "name": manifest["name"],
            "description": manifest.get("description", ""),
            "provenance": manifest["provenance"],
            "source_categories": manifest["source_types"],
            "event_count": row["event_count"] if row else 0,
            "severity_distribution": severity,
            "category_distribution": categories,
            "created_at": row["created_at"] if row else manifest["provenance"].get("generated_at"),
            "import_status": batch["status"] if batch else "available",
            "last_import_at": batch["completed_at"] if batch else None,
            "last_import": dict(batch) if batch else None,
            "checksum_sha256": manifest["event_file_sha256"],
            "validation_status": "valid" if row and row["status"] == "available" else "manifest_valid",
            "validation_message": "Dataset file checksum matches its manifest.",
        }

    def investigations(self, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        where = "dataset_id = ?" if dataset_id else "1=1"
        args = [dataset_id] if dataset_id else []
        with database_session(self.database_path) as connection:
            total = connection.execute(f"SELECT count(*) FROM investigations WHERE {where}", args).fetchone()[0]
            rows = connection.execute(
                f"""SELECT investigation_id, dataset_id, requested_by, status, agent_config_version,
                           started_at, completed_at, summary
                    FROM investigations WHERE {where} ORDER BY started_at DESC LIMIT ? OFFSET ?""",
                [*args, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item["summary"]) if item["summary"] else None
            item["agents"] = self._agent_states(item["status"], (item["summary"] or {}).get("failed_stage"))
            items.append(item)
        return {"total": total, "limit": limit, "offset": offset, "investigations": items}

    def findings(self, *, dataset_id: str | None = None, investigation_id: str | None = None,
                 limit: int = 100, offset: int = 0) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        clauses, args = self._investigation_filters(dataset_id, investigation_id)
        where = " AND ".join(clauses)
        with database_session(self.database_path) as connection:
            total = connection.execute(
                f"""SELECT count(*) FROM agent_findings f JOIN investigations i ON i.investigation_id=f.investigation_id
                    WHERE {where}""", args,
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT f.finding_id, f.investigation_id, i.dataset_id, f.event_id, f.agent_name,
                           f.severity, f.confidence, f.title, f.explanation, f.evidence_refs, f.created_at,
                           o.normalized_event
                    FROM agent_findings f JOIN investigations i ON i.investigation_id=f.investigation_id
                    JOIN original_events o ON o.event_id=f.event_id WHERE {where}
                    ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                             f.created_at DESC LIMIT ? OFFSET ?""",
                [*args, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["evidence_refs"] = json.loads(item["evidence_refs"])
            item["evidence_event"] = json.loads(item.pop("normalized_event"))
            items.append(item)
        return {"total": total, "limit": limit, "offset": offset, "findings": items}

    def proposals(self, *, dataset_id: str | None = None, status: str | None = None,
                  limit: int = 100, offset: int = 0) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        clauses = ["1=1"]
        args: list[Any] = []
        if dataset_id:
            clauses.append("i.dataset_id = ?")
            args.append(dataset_id)
        if status:
            clauses.append("p.policy_status = ?")
            args.append(status)
        where = " AND ".join(clauses)
        with database_session(self.database_path) as connection:
            total = connection.execute(
                f"""SELECT count(*) FROM response_proposals p JOIN investigations i
                    ON i.investigation_id=p.investigation_id WHERE {where}""", args,
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT p.proposal_id, p.investigation_id, i.dataset_id, p.finding_id, p.action_type,
                           p.parameters, p.rationale, p.policy_status, p.created_at,
                           f.event_id, f.severity, f.confidence, f.title,
                           o.normalized_event,
                           (SELECT approval_id FROM approval_records a WHERE a.proposal_id=p.proposal_id
                            ORDER BY a.decided_at DESC LIMIT 1) AS approval_id,
                           (SELECT decision FROM approval_records a WHERE a.proposal_id=p.proposal_id
                            ORDER BY a.decided_at DESC LIMIT 1) AS latest_decision,
                           (SELECT execution_id FROM execution_records x WHERE x.proposal_id=p.proposal_id
                            ORDER BY x.started_at DESC LIMIT 1) AS execution_id,
                           (SELECT status FROM execution_records x WHERE x.proposal_id=p.proposal_id
                            ORDER BY x.started_at DESC LIMIT 1) AS execution_status
                    FROM response_proposals p JOIN investigations i ON i.investigation_id=p.investigation_id
                    LEFT JOIN agent_findings f ON f.finding_id=p.finding_id
                    LEFT JOIN original_events o ON o.event_id=f.event_id
                    WHERE {where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?""",
                [*args, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["parameters"] = json.loads(item["parameters"])
            item["evidence_event"] = json.loads(item.pop("normalized_event")) if item["normalized_event"] else None
            items.append(item)
        return {"total": total, "limit": limit, "offset": offset, "proposals": items}

    def processed_events(self, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        where, args = self._dataset_where(dataset_id, "i.dataset_id")
        with database_session(self.database_path) as connection:
            total = connection.execute(
                f"""SELECT count(*) FROM processed_events p JOIN investigations i
                    ON i.investigation_id=p.investigation_id WHERE {where}""", args,
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT p.processed_event_id, p.original_event_id, p.investigation_id, i.dataset_id,
                           p.finding_id, p.execution_id, p.status, p.before_state, p.after_state, p.created_at,
                           x.proposal_id, x.approval_id, x.mode, x.status AS execution_status, x.outcome,
                           a.decision AS approval_status
                    FROM processed_events p JOIN investigations i ON i.investigation_id=p.investigation_id
                    LEFT JOIN execution_records x ON x.execution_id=p.execution_id
                    LEFT JOIN approval_records a ON a.approval_id=x.approval_id
                    WHERE {where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?""",
                [*args, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            for field in ("before_state", "after_state", "outcome"):
                item[field] = json.loads(item[field]) if item[field] else None
            items.append(item)
        return {"total": total, "limit": limit, "offset": offset, "processed_events": items}

    def audit_history(self, *, dataset_id: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        self._validate_dataset(dataset_id)
        with database_session(self.database_path) as connection:
            where, args = self._dataset_where(dataset_id, "dataset_id")
            audit = [dict(row) for row in connection.execute(
                f"SELECT audit_id AS id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at FROM audit_logs WHERE {where}", args
            ).fetchall()]
            hunts = []
            hunt_clauses = ["1=1"]
            hunt_args: list[Any] = []
            if dataset_id:
                hunt_clauses.append("i.dataset_id = ?")
                hunt_args.append(dataset_id)
            for row in connection.execute(
                f"""SELECT q.query_id, q.investigation_id, q.query_text, q.result_count, q.created_at, i.dataset_id
                    FROM hunting_queries q JOIN investigations i ON i.investigation_id=q.investigation_id
                    WHERE {' AND '.join(hunt_clauses)}""", hunt_args
            ).fetchall():
                hunts.append({"id": row["query_id"], "actor": "threat_hunter", "action": "hunting.query_completed",
                              "resource_type": "hunting_query", "resource_id": row["query_id"], "dataset_id": row["dataset_id"],
                              "details": json.dumps({"query": row["query_text"], "result_count": row["result_count"]}),
                              "occurred_at": row["created_at"]})
        combined = sorted(audit + hunts, key=lambda item: item["occurred_at"], reverse=True)
        return {"total": len(combined), "limit": limit, "offset": offset, "events": combined[offset:offset + limit]}

    def reports(self, dataset_id: str | None = None) -> dict[str, Any]:
        overview = self.overview(dataset_id)
        where, args = self._dataset_where(dataset_id, "i.dataset_id")
        with database_session(self.database_path) as connection:
            agent_rows = connection.execute(
                f"""SELECT f.agent_name, count(*) AS findings, avg(f.confidence) AS avg_confidence
                    FROM agent_findings f JOIN investigations i ON i.investigation_id=f.investigation_id
                    WHERE {where} GROUP BY f.agent_name ORDER BY f.agent_name""", args,
            ).fetchall()
            execution_where = "i.dataset_id = ?" if dataset_id else "1=1"
            execution_args = [dataset_id] if dataset_id else []
            executions = [dict(row) for row in connection.execute(
                f"""SELECT x.status AS label, count(*) AS count FROM execution_records x
                    JOIN response_proposals p ON p.proposal_id=x.proposal_id
                    JOIN investigations i ON i.investigation_id=p.investigation_id
                    WHERE {execution_where} GROUP BY x.status ORDER BY x.status""",
                execution_args,
            ).fetchall()]
            truth_where = "o.dataset_id = ?" if dataset_id else "1=1"
            truth_args = [dataset_id] if dataset_id else []
            truth_rows = connection.execute(
                f"""SELECT gt.event_id, gt.label FROM ground_truth_labels gt
                    JOIN original_events o ON o.event_id=gt.event_id
                    JOIN investigations i ON i.dataset_id=o.dataset_id AND i.status='completed'
                    WHERE {truth_where} GROUP BY gt.event_id, gt.label""",
                truth_args,
            ).fetchall()
            detected_rows = connection.execute(
                f"""SELECT DISTINCT f.event_id FROM agent_findings f
                    JOIN investigations i ON i.investigation_id=f.investigation_id AND i.status='completed'
                    WHERE {where}""", args,
            ).fetchall()
        detected = {row["event_id"] for row in detected_rows}
        evaluation = self._evaluation_metrics(truth_rows, detected) if truth_rows else None
        return {
            "dataset_id": dataset_id,
            "generated_at": self._now(),
            "overview": overview,
            "agent_performance": [dict(row) for row in agent_rows],
            "remediation_executions": executions,
            "ground_truth_evaluation_available": evaluation is not None,
            "ground_truth_evaluation": evaluation,
            "ground_truth_evaluation_note": None if evaluation else "No completed-investigation evaluation labels are available.",
        }

    def settings_summary(self) -> dict[str, Any]:
        file_size = self.database_path.stat().st_size if self.database_path.exists() else 0
        with database_session(self.database_path) as connection:
            dataset_count = connection.execute("SELECT count(*) FROM datasets").fetchone()[0]
            event_count = connection.execute("SELECT count(*) FROM original_events").fetchone()[0]
        return {
            "application_version": "0.1.0",
            "storage": "Local SQLite",
            "database_file": self.database_path.name,
            "database_size_bytes": file_size,
            "dataset_count": dataset_count,
            "event_count": event_count,
            "ai_provider": self.settings.llm_provider,
            "api_credentials_configured": bool(self.settings.llm_api_key),
            "credentials_exposed": False,
            "theme_preference": "stored in this browser",
            "available_datasets": self.datasets.list_datasets(),
        }

    def _validate_dataset(self, dataset_id: str | None) -> None:
        if dataset_id:
            self.datasets.require_dataset(dataset_id)

    @staticmethod
    def _dataset_where(dataset_id: str | None, column: str) -> tuple[str, list[Any]]:
        return (f"{column} = ?", [dataset_id]) if dataset_id else ("1=1", [])

    @staticmethod
    def _group_counts(connection: sqlite3.Connection, table: str, column: str,
                      where: str, args: list[Any]) -> list[dict[str, Any]]:
        return [dict(row) for row in connection.execute(
            f"SELECT {column} AS label, count(*) AS count FROM {table} WHERE {where} GROUP BY {column} ORDER BY count DESC, label",
            args,
        ).fetchall()]

    @staticmethod
    def _investigation_counts(connection: sqlite3.Connection, dataset_id: str | None) -> dict[str, int]:
        where, args = DashboardDataService._dataset_where(dataset_id, "dataset_id")
        rows = connection.execute(
            f"SELECT status, count(*) AS count FROM investigations WHERE {where} GROUP BY status", args
        ).fetchall()
        by_status = {row["status"]: row["count"] for row in rows}
        active = sum(count for status, count in by_status.items() if status.endswith("_running") or status == "in_progress")
        return {
            "total": sum(by_status.values()),
            "completed": by_status.get("completed", 0),
            "in_progress": active,
            "failed": by_status.get("failed", 0),
        }

    @staticmethod
    def _recent_investigations(connection: sqlite3.Connection, dataset_id: str | None, limit: int) -> list[dict[str, Any]]:
        where, args = DashboardDataService._dataset_where(dataset_id, "dataset_id")
        rows = connection.execute(
            f"""SELECT investigation_id, dataset_id, requested_by, status, started_at, completed_at, summary
                FROM investigations WHERE {where} ORDER BY started_at DESC LIMIT ?""", [*args, limit]
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["summary"] = json.loads(item["summary"]) if item["summary"] else None
            items.append(item)
        return items

    @staticmethod
    def _recent_findings(connection: sqlite3.Connection, dataset_id: str | None, limit: int) -> list[dict[str, Any]]:
        where, args = DashboardDataService._dataset_where(dataset_id, "i.dataset_id")
        return [dict(row) for row in connection.execute(
            f"""SELECT f.finding_id, i.dataset_id, f.investigation_id, f.event_id, f.severity,
                       f.confidence, f.title, f.created_at
                FROM agent_findings f JOIN investigations i ON i.investigation_id=f.investigation_id
                WHERE {where} ORDER BY f.created_at DESC LIMIT ?""", [*args, limit]
        ).fetchall()]

    @staticmethod
    def _investigation_filters(dataset_id: str | None, investigation_id: str | None) -> tuple[list[str], list[Any]]:
        clauses = ["1=1"]
        args: list[Any] = []
        if dataset_id:
            clauses.append("i.dataset_id = ?")
            args.append(dataset_id)
        if investigation_id:
            clauses.append("i.investigation_id = ?")
            args.append(investigation_id)
        return clauses, args

    @staticmethod
    def _agent_states(status: str, failed_stage: str | None = None) -> dict[str, str]:
        stages = ("threat_investigator", "threat_hunter", "response_planner")
        active_stage = {"agent1_running": 0, "agent2_running": 1, "agent3_running": 2}.get(status)
        if status == "completed":
            return {stage: "completed" for stage in stages}
        if status == "failed":
            failed_index = stages.index(failed_stage) if failed_stage in stages else None
            if failed_index is None:
                return {stage: "failed_or_not_run" for stage in stages}
            return {
                stage: "failed" if index == failed_index else ("completed" if index < failed_index else "not_run")
                for index, stage in enumerate(stages)
            }
        if active_stage is None:
            return {stage: "waiting" for stage in stages}
        return {
            stage: "running" if index == active_stage else ("completed" if index < active_stage else "waiting")
            for index, stage in enumerate(stages)
        }

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _evaluation_metrics(truth_rows, detected: set[str]) -> dict[str, Any]:
        positive = {"malicious", "suspicious"}
        tp = fp = fn = tn = 0
        for row in truth_rows:
            is_positive = row["label"] in positive
            is_detected = row["event_id"] in detected
            if is_positive and is_detected:
                tp += 1
            elif is_positive:
                fn += 1
            elif is_detected:
                fp += 1
            else:
                tn += 1
        total = tp + fp + fn + tn
        return {
            "evaluated_events": total,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "detection_accuracy": round((tp + tn) / total, 4) if total else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "labels_disclosed": False,
        }
