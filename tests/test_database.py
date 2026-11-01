"""Tests for the initial SQLite foundation."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from backend.database import connect, database_session, initialize_database


class DatabaseFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.database = Path(self.temp_dir.name) / "security.db"
        initialize_database(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialization_creates_core_tables_and_is_idempotent(self):
        initialize_database(self.database)

        with closing(connect(self.database)) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue({"datasets", "original_events", "investigations", "processed_events", "ground_truth_labels"} <= tables)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")

    def test_foreign_keys_reject_orphan_events(self):
        with closing(connect(self.database)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT INTO original_events
                       (event_id, dataset_id, event_time, ingested_at, source_type, severity,
                        category, normalized_event, raw_event, event_sha256, provenance)
                       VALUES ('e1', 'missing', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                               'test', 'low', 'test', '{}', '{}', 'hash', 'synthetic')"""
                )

    def test_database_session_rolls_back_errors(self):
        with self.assertRaises(RuntimeError):
            with database_session(self.database) as connection:
                connection.execute(
                    "INSERT INTO datasets(dataset_id, name, provenance, created_at) VALUES ('d1', 'test', 'synthetic', 'now')"
                )
                raise RuntimeError("force rollback")

        with closing(connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM datasets").fetchone()[0], 0)
