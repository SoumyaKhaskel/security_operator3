"""Read dataset manifests and register their public metadata in SQLite."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.database import database_session


class DatasetNotFoundError(LookupError):
    """Raised when an explicitly selected dataset is unavailable."""


class DatasetService:
    def __init__(self, library_dir: str | Path, database_path: str | Path):
        self.library_dir = Path(library_dir)
        self.database_path = Path(database_path)

    def _index(self) -> dict[str, Any]:
        path = self.library_dir / "manifest.json"
        if not path.is_file():
            raise FileNotFoundError(f"Dataset library manifest not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def list_datasets(self) -> list[dict[str, Any]]:
        """Return selectable, non-sensitive dataset metadata."""
        return [
            {
                "dataset_id": item["dataset_id"],
                "name": item["name"],
                "event_count": item["event_count"],
                "provenance": item["provenance"],
            }
            for item in self._index()["datasets"]
        ]

    def get_manifest(self, dataset_id: str) -> dict[str, Any]:
        for item in self._index()["datasets"]:
            if item["dataset_id"] == dataset_id:
                path = self.library_dir / item["manifest"]
                manifest = json.loads(path.read_text(encoding="utf-8"))
                if manifest["dataset_id"] != dataset_id:
                    raise ValueError("Dataset manifest ID does not match its library index")
                event_path = path.parent / manifest["event_file"]
                digest = hashlib.sha256(event_path.read_bytes()).hexdigest()
                if digest != manifest["event_file_sha256"]:
                    raise ValueError(f"Dataset checksum mismatch for {dataset_id}")
                return manifest
        raise DatasetNotFoundError(dataset_id)

    def get_event_file_path(self, dataset_id: str) -> Path:
        """Return the event file path relative to its dataset-specific manifest."""
        for item in self._index()["datasets"]:
            if item["dataset_id"] == dataset_id:
                manifest_path = self.library_dir / item["manifest"]
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest["dataset_id"] != dataset_id:
                    raise ValueError("Dataset manifest ID does not match its library index")
                return manifest_path.parent / manifest["event_file"]
        raise DatasetNotFoundError(dataset_id)

    def get_public_dataset(self, dataset_id: str) -> dict[str, Any]:
        for item in self.list_datasets():
            if item["dataset_id"] == dataset_id:
                return item
        raise DatasetNotFoundError(dataset_id)

    def register_library(self) -> list[dict[str, Any]]:
        """Synchronize available manifest metadata into the application database."""
        datasets = self.list_datasets()
        for dataset in datasets:
            manifest = self.get_manifest(dataset["dataset_id"])
            provenance = json.dumps(manifest["provenance"], sort_keys=True)
            created_at = manifest["provenance"].get("generated_at", datetime.now().astimezone().isoformat())
            with database_session(self.database_path) as connection:
                connection.execute(
                    """INSERT INTO datasets(dataset_id, name, description, provenance, source_uri,
                              sha256, event_count, created_at, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'available')
                       ON CONFLICT(dataset_id) DO UPDATE SET name=excluded.name,
                         description=excluded.description, provenance=excluded.provenance,
                         source_uri=excluded.source_uri, sha256=excluded.sha256,
                         event_count=excluded.event_count, status='available'""",
                    (
                        dataset["dataset_id"],
                        dataset["name"],
                        manifest.get("description", ""),
                        provenance,
                        manifest["event_file"],
                        manifest["event_file_sha256"],
                        manifest["event_count"],
                        created_at,
                    ),
                )
        return datasets

    def require_dataset(self, dataset_id: str) -> dict[str, Any]:
        return self.get_manifest(dataset_id)
