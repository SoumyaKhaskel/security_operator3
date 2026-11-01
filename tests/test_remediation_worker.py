"""Simulation execution authorization, idempotency, and comparison tests."""

import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from agents.orchestrator import InvestigationOrchestrator
from agents.providers.mock import DeterministicMockProvider
from backend.database import connect, initialize_database
from backend.services.datasets import DatasetService
from backend.services.investigations import InvestigationService
from ingestion.service import IngestionService
from policy_engine.review import ProposalReviewService
from remediation_worker.worker import ExecutionConflict, ExecutionNotAuthorized, SimulationRemediationWorker


ROOT = Path(__file__).resolve().parents[1]


class RemediationWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "db" / "security.db"
        initialize_database(self.database)
        self.datasets = DatasetService(ROOT / "data" / "datasets", self.database)
        self.datasets.register_library()
        source = self.root / "event.jsonl"
        event = {
            "event_id": "execution-event",
            "event_time": "2026-10-31T10:00:00Z",
            "source": {"type": "windows_security", "origin": "synthetic"},
            "host": {"hostname": "WIN-EXEC-01"},
            "actor": {"username": "analyst", "ip": "192.0.2.44"},
            "event": {"category": "windows_security", "type": "encoded_powershell", "severity": "critical"},
            "message": "Suspicious process recorded.",
        }
        source.write_text(json.dumps(event) + "\n", encoding="utf-8")
        IngestionService(self.database, self.root / "quarantine", self.datasets).import_file("DATASET-001", source)
        investigation = InvestigationService(self.database, self.datasets).start("DATASET-001", "analyst")
        output = InvestigationOrchestrator(self.database, DeterministicMockProvider()).run(investigation["investigation_id"])
        self.proposal = output.proposals[0]
        self.review = ProposalReviewService(self.database)
        self.worker = SimulationRemediationWorker(self.database, self.review)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _approve(self):
        return self.review.decide(self.proposal.proposal_id, reviewer="reviewer-a", decision="approved")

    def test_approved_proposal_executes_once_and_preserves_original(self):
        approval = self._approve()
        execution = self.worker.execute(self.proposal.proposal_id, approval["approval_id"], "exec-key-1")
        retry = self.worker.execute(self.proposal.proposal_id, approval["approval_id"], "exec-key-1")
        self.assertEqual(execution["execution_id"], retry["execution_id"])
        self.assertEqual(execution["mode"], "simulation")
        self.assertEqual(execution["status"], "simulated_success")
        self.assertTrue(execution["outcome"]["original_event_unchanged"])

        comparison = self.worker.comparison(execution["execution_id"])["comparison"]
        self.assertEqual(comparison["status"], "simulated_execution_successful")
        self.assertEqual(comparison["before_state"]["status"], "uninvestigated")
        self.assertEqual(comparison["after_state"]["status"], "resolved")
        self.assertEqual(comparison["after_state"]["simulation"]["mode"], "simulation")
        self.assertEqual(comparison["before_state"]["event_id"], comparison["after_state"]["event_id"])

        with closing(connect(self.database)) as connection:
            original = json.loads(connection.execute(
                "SELECT normalized_event FROM original_events WHERE event_id=?", ("DATASET-001-execution-event",)
            ).fetchone()[0])
            self.assertEqual(original["status"], "uninvestigated")
            self.assertEqual(connection.execute("SELECT count(*) FROM execution_records").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM processed_events").fetchone()[0], 1)

        with self.assertRaises(ExecutionConflict):
            self.worker.execute(self.proposal.proposal_id, approval["approval_id"], "exec-key-2")
        with self.assertRaises(ExecutionConflict):
            self.worker.execute("another-proposal", "another-approval", "exec-key-1")

    def test_pending_or_denied_proposals_cannot_execute(self):
        with self.assertRaises(ExecutionNotAuthorized):
            self.worker.execute(self.proposal.proposal_id, "APR-not-approved", "pending-key")
        denial = self.review.decide(self.proposal.proposal_id, reviewer="reviewer-a", decision="denied")
        with self.assertRaises(ExecutionNotAuthorized):
            self.worker.execute(self.proposal.proposal_id, denial["approval_id"], "denied-key")

    def test_invalid_idempotency_key_is_rejected(self):
        with self.assertRaises(ValueError):
            self.worker.execute(self.proposal.proposal_id, "APR-not-approved", "invalid key with spaces")


if __name__ == "__main__":
    unittest.main()
