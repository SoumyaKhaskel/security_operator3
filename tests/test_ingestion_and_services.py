"""Integration tests for file imports, dataset scoping, and investigations."""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from backend.database import connect, initialize_database
from backend.services.datasets import DatasetNotFoundError, DatasetService
from backend.services.events import EventService
from backend.services.investigations import InvestigationService
from ingestion.service import IngestionService


ROOT = Path(__file__).resolve().parents[1]


class IngestionAndServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "db" / "security.db"
        self.library = DatasetService(ROOT / "data" / "datasets", self.database)
        initialize_database(self.database)
        self.library.register_library()
        self.ingestion = IngestionService(self.database, self.root / "quarantine", self.library)
        self.events = EventService(self.database, self.library)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_jsonl_import_duplicates_quarantine_and_original_immutability(self):
        path = self.root / "events.jsonl"
        good = {
            "event_id": "custom-1",
            "timestamp": "2026-10-31T10:00:00+05:30",
            "source_type": "linux_auth",
            "severity": "high",
            "event_type": "ssh_failure",
            "message": "Failed SSH login",
        }
        with path.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(good) + "\n")
            stream.write(json.dumps(good) + "\n")
            stream.write(json.dumps({"event_id": "missing-time"}) + "\n")
            stream.write(json.dumps({**good, "event_id": "custom-2", "timestamp": "2026-10-30T00:00:00Z"}) + "\n")

        result = self.ingestion.import_file("DATASET-001", path)
        self.assertEqual(result["accepted_count"], 2)
        self.assertEqual(result["duplicate_count"], 1)
        self.assertEqual(result["rejected_count"], 1)
        self.assertTrue((self.root / "quarantine" / result["quarantine_file"]).is_file())
        page = self.events.search("DATASET-001")
        self.assertEqual(page["total"], 2)
        event = page["events"][0]
        self.assertEqual(event["event_id"], "DATASET-001-custom-1")
        self.assertEqual(event["event_time"], "2026-10-31T04:30:00Z")
        self.assertEqual(event["raw_event"]["timestamp"], good["timestamp"])
        self.assertEqual(event["dataset_id"], "DATASET-001")

        with closing(connect(self.database)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE original_events SET normalized_event='{}' WHERE event_id='DATASET-001-custom-1'")

    def test_json_and_csv_import_and_dataset_scoping(self):
        json_path = self.root / "source.json"
        json_path.write_text(json.dumps([{
            "event_id": "shared-1",
            "event_time": "2026-10-31T01:00:00Z",
            "source": {"type": "cloud_audit", "product": "test"},
            "event": {"category": "cloud_audit", "type": "api_call", "severity": "medium"},
            "message": "Inventory read",
        }]), encoding="utf-8")
        self.assertEqual(self.ingestion.import_file("DATASET-001", json_path)["accepted_count"], 1)

        csv_path = self.root / "source.csv"
        csv_path.write_text(
            "event_id,timestamp,source_type,category,event_type,severity,hostname,actor_username\n"
            "shared-1,2026-10-31T00:00:00Z,windows_security,authentication,login,low,WIN-TEST-01,analyst\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ingestion.import_file("DATASET-002", csv_path)["accepted_count"], 1)

        first = self.events.search("DATASET-001")
        self.assertEqual(first["total"], 1)
        self.assertEqual(first["events"][0]["event_id"], "DATASET-001-shared-1")
        second = self.events.search("DATASET-002")
        self.assertEqual(second["total"], 1)
        self.assertEqual(second["events"][0]["event_id"], "DATASET-002-shared-1")
        self.assertEqual(second["events"][0]["host"]["hostname"], "WIN-TEST-01")
        self.assertEqual(self.events.search("DATASET-002", severity="low")["total"], 1)
        self.assertEqual(self.events.search("DATASET-002", query="absent")["total"], 0)
        with self.assertRaises(DatasetNotFoundError):
            self.events.search("DATASET-UNKNOWN")

    def test_investigation_requires_a_valid_explicit_dataset(self):
        service = InvestigationService(self.database, self.library)
        investigation = service.start("DATASET-003", "local-analyst")
        self.assertTrue(investigation["investigation_id"].startswith("INV-"))
        self.assertEqual(investigation["dataset_id"], "DATASET-003")
        self.assertEqual(investigation["status"], "in_progress")
        with self.assertRaises(DatasetNotFoundError):
            service.start("DATASET-NOT-SELECTED", "local-analyst")


if __name__ == "__main__":
    unittest.main()
