"""Explicitly started, dataset-bound investigation records."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from backend.database import database_session
from backend.clock import utc_now_iso
from backend.services.datasets import DatasetService


class InvestigationService:
    def __init__(self, database_path: str | Path, dataset_service: DatasetService):
        self.database_path = Path(database_path)
        self.dataset_service = dataset_service

    def start(self, dataset_id: str, requested_by: str) -> dict[str, Any]:
        """Start an investigation only for the caller's explicit dataset ID."""
        self.dataset_service.require_dataset(dataset_id)
        if not requested_by.strip():
            raise ValueError("requested_by is required")
        investigation_id = f"INV-{uuid.uuid4()}"
        started_at = utc_now_iso()
        with database_session(self.database_path) as connection:
            connection.execute(
                """INSERT INTO investigations
                   (investigation_id, dataset_id, requested_by, status, agent_config_version, started_at)
                   VALUES (?, ?, ?, 'in_progress', 'v1', ?)""",
                (investigation_id, dataset_id, requested_by.strip(), started_at),
            )
            connection.execute(
                """INSERT INTO audit_logs
                   (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                   VALUES (?, ?, 'investigation.created', 'investigation', ?, ?, '{}', ?)""",
                (f"AUD-{investigation_id}-CREATED", requested_by.strip(), investigation_id, dataset_id, started_at),
            )
        return {
            "investigation_id": investigation_id,
            "dataset_id": dataset_id,
            "requested_by": requested_by.strip(),
            "status": "in_progress",
            "started_at": started_at,
        }
