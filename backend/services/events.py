"""Dataset-scoped event search backed only by the original evidence table."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.database import database_session
from backend.services.datasets import DatasetNotFoundError, DatasetService


class EventService:
    def __init__(self, database_path: str | Path, dataset_service: DatasetService):
        self.database_path = Path(database_path)
        self.dataset_service = dataset_service

    def search(
        self,
        dataset_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        category: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        self.dataset_service.require_dataset(dataset_id)
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset cannot be negative")

        clauses = ["dataset_id = ?"]
        parameters: list[Any] = [dataset_id]
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity.lower())
        if category:
            clauses.append("category = ?")
            parameters.append(category)
        if query:
            clauses.append("(normalized_event LIKE ? OR raw_event LIKE ?)")
            search_term = f"%{query[:200]}%"
            parameters.extend((search_term, search_term))
        where = " AND ".join(clauses)

        with database_session(self.database_path) as connection:
            total = connection.execute(
                f"SELECT count(*) FROM original_events WHERE {where}", parameters
            ).fetchone()[0]
            rows = connection.execute(
                f"""SELECT event_id, event_time, ingested_at, source_type, severity,
                           category, normalized_event
                    FROM original_events WHERE {where}
                    ORDER BY event_time DESC, event_id LIMIT ? OFFSET ?""",
                [*parameters, limit, offset],
            ).fetchall()
        return {
            "dataset_id": dataset_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": [json.loads(row["normalized_event"]) for row in rows],
        }
