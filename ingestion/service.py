"""Validated imports into immutable original-event storage."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from backend.database import database_session
from backend.clock import utc_now_iso
from backend.services.datasets import DatasetService
from ingestion.normalizer import MAX_FILE_BYTES, RecordNormalizationError, iter_normalized_records


class IngestionService:
    def __init__(
        self,
        database_path: str | Path,
        quarantine_dir: str | Path,
        dataset_service: DatasetService,
    ):
        self.database_path = Path(database_path)
        self.quarantine_dir = Path(quarantine_dir)
        self.dataset_service = dataset_service

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def import_file(self, dataset_id: str, file_path: str | Path, *, source_name: str | None = None) -> dict[str, Any]:
        """Import an explicitly selected file into exactly one selected dataset."""
        self.dataset_service.require_dataset(dataset_id)
        self.dataset_service.register_library()
        path = Path(file_path)
        display_name = source_name or path.name
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte import limit")
        batch_id = f"BATCH-{uuid.uuid4()}"
        started_at = utc_now_iso()
        file_hash = self._file_hash(path)
        accepted = duplicates = rejected = 0
        quarantine: list[dict[str, Any]] = []
        with database_session(self.database_path) as connection:
            connection.execute(
                """INSERT INTO ingestion_batches
                   (batch_id, dataset_id, source_name, source_format, file_sha256, started_at, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'processing')""",
                (batch_id, dataset_id, display_name, path.suffix.lower().lstrip("."), file_hash, started_at),
            )

        for record in iter_normalized_records(str(path), dataset_id):
            if isinstance(record, RecordNormalizationError):
                rejected += 1
                quarantine.append(
                    {
                        "batch_id": batch_id,
                        "dataset_id": dataset_id,
                        "record_number": record.record_number,
                        "error": str(record),
                        "raw_record": record.raw_record,
                    }
                )
                continue
            event = record
            data = event.model_dump(mode="json", exclude_none=True)
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            with database_session(self.database_path) as connection:
                cursor = connection.execute(
                    """INSERT OR IGNORE INTO original_events
                       (event_id, dataset_id, batch_id, event_time, ingested_at, source_type,
                        severity, category, normalized_event, raw_event, event_sha256, provenance)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.event_id,
                        dataset_id,
                        batch_id,
                        data["event_time"],
                        data["ingested_at"],
                        event.source.type,
                        event.event.severity,
                        event.event.category,
                        canonical,
                        json.dumps(event.raw_event, sort_keys=True),
                        event_hash,
                        event.source.origin,
                    ),
                )
                if cursor.rowcount:
                    accepted += 1
                else:
                    duplicates += 1

        completed_at = utc_now_iso()
        status = "completed_with_rejections" if rejected else "completed"
        if quarantine:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            quarantine_path = self.quarantine_dir / f"{batch_id}.jsonl"
            with quarantine_path.open("w", encoding="utf-8", newline="\n") as stream:
                for item in quarantine:
                    stream.write(json.dumps(item, sort_keys=True) + "\n")
        with database_session(self.database_path) as connection:
            connection.execute(
                """UPDATE ingestion_batches SET completed_at=?, accepted_count=?, rejected_count=?, status=?
                   WHERE batch_id=?""",
                (completed_at, accepted, rejected, status, batch_id),
            )
            connection.execute(
                "UPDATE datasets SET event_count=(SELECT count(*) FROM original_events WHERE dataset_id=?) WHERE dataset_id=?",
                (dataset_id, dataset_id),
            )
            connection.execute(
                """INSERT INTO audit_logs
                   (audit_id, actor, action, resource_type, resource_id, dataset_id, details, occurred_at)
                   VALUES (?, 'ingestion_service', 'dataset.import_completed', 'ingestion_batch', ?, ?, ?, ?)""",
                (
                    f"AUD-{batch_id}",
                    batch_id,
                    dataset_id,
                    json.dumps({"filename": display_name, "file_sha256": file_hash, "accepted_count": accepted,
                                "duplicate_count": duplicates, "rejected_count": rejected, "status": status}, sort_keys=True),
                    completed_at,
                ),
            )
        return {
            "batch_id": batch_id,
            "dataset_id": dataset_id,
            "filename": display_name,
            "file_sha256": file_hash,
            "accepted_count": accepted,
            "duplicate_count": duplicates,
            "rejected_count": rejected,
            "status": status,
            "quarantine_file": f"{batch_id}.jsonl" if quarantine else None,
        }
