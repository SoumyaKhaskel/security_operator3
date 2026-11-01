"""Read-only SQLite view permanently bound to one selected dataset."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class DatasetScopeViolation(PermissionError):
    """Raised when code attempts to use an event view for another dataset."""


class ReadOnlyDatasetView:
    """Expose only paginated original events and restricted event searches."""

    def __init__(self, database_path: str | Path, dataset_id: str):
        if not dataset_id:
            raise ValueError("dataset_id must be explicitly selected")
        self.dataset_id = dataset_id
        uri = f"{Path(database_path).resolve().as_uri()}?mode=ro"
        self._connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA query_only = ON")

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "ReadOnlyDatasetView":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def count_events(self) -> int:
        return self._connection.execute(
            "SELECT count(*) FROM original_events WHERE dataset_id = ?", (self.dataset_id,)
        ).fetchone()[0]

    def list_events(self, *, limit: int = 250, offset: int = 0) -> list[dict[str, Any]]:
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("event page must have limit 1-500 and a non-negative offset")
        rows = self._connection.execute(
            """SELECT normalized_event FROM original_events
               WHERE dataset_id = ? ORDER BY event_time, event_id LIMIT ? OFFSET ?""",
            (self.dataset_id, limit, offset),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def search_events(
        self,
        *,
        category: str | None = None,
        severity: str | None = None,
        needle: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("hunt result limit must be between 1 and 100")
        clauses = ["dataset_id = ?"]
        parameters: list[Any] = [self.dataset_id]
        if category:
            clauses.append("category = ?")
            parameters.append(category)
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity)
        if needle:
            clauses.append("normalized_event LIKE ?")
            parameters.append(f"%{needle[:160]}%")
        rows = self._connection.execute(
            f"""SELECT normalized_event FROM original_events
                WHERE {' AND '.join(clauses)} ORDER BY event_time, event_id LIMIT ?""",
            [*parameters, limit],
        ).fetchall()
        return [json.loads(row[0]) for row in rows]
