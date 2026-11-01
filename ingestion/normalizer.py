"""Normalize JSONL, JSON, and CSV rows into the common event model."""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterator

from pydantic import ValidationError

from backend.events import SecurityEvent


MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024


class RecordNormalizationError(ValueError):
    def __init__(self, message: str, record_number: int, raw_record: str):
        super().__init__(message)
        self.record_number = record_number
        self.raw_record = raw_record


def _pick(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _normalize_record(raw: dict[str, Any], dataset_id: str, source_format: str, record_number: int) -> SecurityEvent:
    original = dict(raw)
    data = dict(raw)
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    details = data.get("event") if isinstance(data.get("event"), dict) else {}
    timestamp = _pick(data, "event_time", "timestamp", "@timestamp", "observed_at")
    if not timestamp:
        raise ValueError("event timestamp is required")
    ingested_at = _pick(data, "ingested_at") or datetime.now(timezone.utc).isoformat()

    canonical_raw = json.dumps(original, sort_keys=True, separators=(",", ":"), default=str)
    fallback_id = f"{dataset_id}-IMPORT-{hashlib.sha256(canonical_raw.encode('utf-8')).hexdigest()[:20]}"
    source_event_id = str(_pick(data, "event_id", "id") or fallback_id)
    event_id = source_event_id if source_event_id.startswith(f"{dataset_id}-") else f"{dataset_id}-{source_event_id}"
    if len(event_id) > 256:
        event_id = f"{dataset_id}-IMPORT-{hashlib.sha256(source_event_id.encode('utf-8')).hexdigest()}"
    severity = str(_pick(details, "severity") or _pick(data, "severity") or "unknown").lower()
    severity = {"info": "informational", "warning": "medium", "notice": "low"}.get(severity, severity)
    event = {
        "schema_version": data.get("schema_version", "1.0"),
        "event_id": event_id,
        "dataset_id": dataset_id,
        "event_time": timestamp,
        "ingested_at": ingested_at,
        "source": {
            **source,
            "type": _pick(source, "type") or _pick(data, "source_type", "log_source") or "unknown",
            "format": source_format,
            "origin": _pick(source, "origin") or "imported",
            "product": _pick(source, "product"),
        },
        "host": data.get("host") if isinstance(data.get("host"), dict) else (
            {"hostname": _pick(data, "hostname", "host_name")} if _pick(data, "hostname", "host_name") else None
        ),
        "event": {
            **details,
            "category": _pick(details, "category") or _pick(data, "category", "event_category") or "unknown",
            "type": _pick(details, "type") or _pick(data, "type", "event_type") or "unknown",
            "action": _pick(details, "action") or _pick(data, "action"),
            "outcome": _pick(details, "outcome") or _pick(data, "outcome"),
            "severity": severity,
        },
        "actor": data.get("actor") if isinstance(data.get("actor"), dict) else None,
        "target": data.get("target") if isinstance(data.get("target"), dict) else None,
        "network": data.get("network") if isinstance(data.get("network"), dict) else None,
        "threat": data.get("threat") if isinstance(data.get("threat"), dict) else None,
        "message": _pick(data, "message", "description"),
        "raw_event": original,
        "labels": data.get("labels") if isinstance(data.get("labels"), list) else [],
        "status": data.get("status", "uninvestigated"),
    }
    for key in ("host", "actor", "target", "network", "threat", "message"):
        if event[key] is None:
            event.pop(key)
    return SecurityEvent.model_validate(event)


def _csv_row(row: dict[str, str]) -> dict[str, Any]:
    """Map common flat CSV headers while retaining every original column."""
    data: dict[str, Any] = {"raw_event": dict(row)}
    aliases = {
        "event_time": ("event_time", "timestamp", "@timestamp", "observed_at"),
        "event_id": ("event_id", "id"),
        "source_type": ("source_type", "log_source", "product_type"),
        "hostname": ("hostname", "host_name", "host"),
        "category": ("category", "event_category"),
        "type": ("type", "event_type"),
        "action": ("action",),
        "outcome": ("outcome",),
        "severity": ("severity",),
        "message": ("message", "description"),
    }
    for target, candidates in aliases.items():
        value = _pick(row, *candidates)
        if value is not None:
            data[target] = value
    if _pick(row, "actor_username", "username", "user"):
        data["actor"] = {"username": _pick(row, "actor_username", "username", "user")}
    if _pick(row, "actor_ip", "source_ip"):
        data["actor"] = {**data.get("actor", {}), "ip": _pick(row, "actor_ip", "source_ip")}
    network = {}
    for key in ("source_ip", "destination_ip", "destination_port", "protocol"):
        if _pick(row, key) is not None:
            network[key] = row[key]
    if network:
        data["network"] = network
    return data


def iter_normalized_records(path: str, dataset_id: str) -> Iterator[SecurityEvent | RecordNormalizationError]:
    """Read one supported file and yield validated records in source order."""
    from pathlib import Path

    source_path = Path(path)
    size = source_path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte import limit")
    suffix = source_path.suffix.lower()
    if suffix not in {".jsonl", ".json", ".csv"}:
        raise ValueError("supported import extensions are .jsonl, .json, and .csv")

    if suffix == ".jsonl":
        with source_path.open("r", encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
                    yield RecordNormalizationError("record exceeds 1 MiB limit", number, line[:MAX_RECORD_BYTES])
                    continue
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError("each JSONL record must be an object")
                    yield _normalize_record(raw, dataset_id, "jsonl", number)
                except (json.JSONDecodeError, ValueError, ValidationError) as exc:
                    yield RecordNormalizationError(str(exc), number, line.rstrip("\r\n"))
    elif suffix == ".json":
        raw_text = source_path.read_text(encoding="utf-8-sig")
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            yield RecordNormalizationError(str(exc), exc.lineno, raw_text[:MAX_RECORD_BYTES])
            return
        records = payload.get("events") if isinstance(payload, dict) and isinstance(payload.get("events"), list) else payload
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            yield RecordNormalizationError("JSON must contain an event object or array", 1, raw_text[:MAX_RECORD_BYTES])
            return
        for number, raw in enumerate(records, start=1):
            serialized = json.dumps(raw, default=str)
            if len(serialized.encode("utf-8")) > MAX_RECORD_BYTES:
                yield RecordNormalizationError("record exceeds 1 MiB limit", number, serialized[:MAX_RECORD_BYTES])
                continue
            try:
                if not isinstance(raw, dict):
                    raise ValueError("each JSON record must be an object")
                yield _normalize_record(raw, dataset_id, "json", number)
            except (ValueError, ValidationError) as exc:
                yield RecordNormalizationError(str(exc), number, serialized)
    else:
        with source_path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            for number, row in enumerate(reader, start=2):
                serialized = json.dumps(row, sort_keys=True)
                if len(serialized.encode("utf-8")) > MAX_RECORD_BYTES:
                    yield RecordNormalizationError("record exceeds 1 MiB limit", number, serialized[:MAX_RECORD_BYTES])
                    continue
                try:
                    yield _normalize_record(_csv_row(row), dataset_id, "csv", number)
                except (ValueError, ValidationError) as exc:
                    yield RecordNormalizationError(str(exc), number, serialized)
