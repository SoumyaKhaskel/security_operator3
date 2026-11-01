"""Database-backed dashboard projections and privacy checks."""

import json
import tempfile
import unittest
from pathlib import Path

from agents.orchestrator import InvestigationOrchestrator
from agents.providers.mock import DeterministicMockProvider
from backend.config import Settings
from backend.dashboard_data import DashboardDataService
from backend.database import initialize_database
from backend.services.datasets import DatasetService
from backend.services.investigations import InvestigationService
from ingestion.service import IngestionService
from policy_engine.review import ProposalReviewService
from remediation_worker.worker import SimulationRemediationWorker


ROOT = Path(__file__).resolve().parents[1]


class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "db" / "security.db"
        initialize_database(self.database)
        self.datasets = DatasetService(ROOT / "data" / "datasets", self.database)
        self.datasets.register_library()
        self.settings = Settings(self.database, "INFO", "mock", "secret-value-must-not-leak")
        self.dashboard = DashboardDataService(self.database, self.datasets, self.settings)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dashboard_metrics_use_stored_state_and_hide_credentials(self):
        self.assertEqual(self.dashboard.overview()["total_events"], 0)
        event_path = self.root / "event.jsonl"
        event = {
            "event_id": "dashboard-event",
            "event_time": "2026-10-31T10:00:00Z",
            "source": {"type": "windows_security", "origin": "synthetic"},
            "host": {"hostname": "WIN-DASH-01"},
            "actor": {"username": "analyst", "ip": "192.0.2.84"},
            "event": {"category": "windows_security", "type": "encoded_powershell", "severity": "critical"},
            "message": "Test security event",
        }
        event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        IngestionService(self.database, self.root / "quarantine", self.datasets).import_file("DATASET-001", event_path)

        overview = self.dashboard.overview("DATASET-001")
        self.assertEqual(overview["total_events"], 1)
        self.assertEqual(overview["critical_high_events"], 1)
        self.assertEqual(overview["provenance_distribution"], [{"label": "synthetic", "count": 1}])
        detail = self.dashboard.dataset_detail("DATASET-001")
        self.assertEqual(detail["event_count"], 1)
        self.assertEqual(detail["validation_status"], "valid")
        self.assertTrue(detail["checksum_sha256"])

        investigation = InvestigationService(self.database, self.datasets).start("DATASET-001", "analyst")
        result = InvestigationOrchestrator(self.database, DeterministicMockProvider()).run(investigation["investigation_id"])
        finding_page = self.dashboard.findings(dataset_id="DATASET-001")
        proposal_page = self.dashboard.proposals(dataset_id="DATASET-001")
        self.assertEqual(finding_page["total"], 1)
        self.assertEqual(proposal_page["total"], 1)
        self.assertEqual(self.dashboard.overview("DATASET-001")["total_findings"], 1)

        proposal = result.proposals[0]
        approval = ProposalReviewService(self.database).decide(
            proposal.proposal_id, reviewer="analyst", decision="approved"
        )
        SimulationRemediationWorker(self.database).execute(
            proposal.proposal_id, approval["approval_id"], "dashboard-exec-key"
        )
        processed = self.dashboard.processed_events(dataset_id="DATASET-001")
        self.assertEqual(processed["total"], 1)
        self.assertEqual(processed["processed_events"][0]["mode"], "simulation")
        audit = self.dashboard.audit_history(dataset_id="DATASET-001")
        actions = {item["action"] for item in audit["events"]}
        self.assertIn("dataset.import_completed", actions)
        self.assertIn("agent.stage_started", actions)
        self.assertIn("proposal.approved", actions)
        self.assertIn("execution.simulated_success", actions)
        report = self.dashboard.reports("DATASET-001")
        self.assertEqual(report["overview"]["total_events"], 1)
        self.assertFalse(report["ground_truth_evaluation_available"])

        settings = self.dashboard.settings_summary()
        encoded = json.dumps(settings)
        self.assertTrue(settings["api_credentials_configured"])
        self.assertNotIn("secret-value-must-not-leak", encoded)
        self.assertNotIn("llm_api_key", settings)


if __name__ == "__main__":
    unittest.main()
