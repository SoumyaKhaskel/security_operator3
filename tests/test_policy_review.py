"""Policy validation and human review workflow tests."""

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
from policy_engine.review import PolicyRejectedError, ProposalDecisionConflict, ProposalReviewService


ROOT = Path(__file__).resolve().parents[1]


class PolicyReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp_dir.name)
        self.database = self.root / "db" / "security.db"
        initialize_database(self.database)
        self.datasets = DatasetService(ROOT / "data" / "datasets", self.database)
        self.datasets.register_library()
        source = self.root / "event.jsonl"
        event = {
            "event_id": "policy-event",
            "event_time": "2026-10-31T10:00:00Z",
            "source": {"type": "windows_security", "origin": "synthetic"},
            "host": {"hostname": "WIN-POLICY-01"},
            "actor": {"username": "analyst", "ip": "192.0.2.90"},
            "event": {"category": "windows_security", "type": "encoded_powershell", "severity": "high"},
            "message": "Encoded script blocked in test environment.",
        }
        source.write_text(json.dumps(event) + "\n", encoding="utf-8")
        IngestionService(self.database, self.root / "quarantine", self.datasets).import_file("DATASET-001", source)
        investigation = InvestigationService(self.database, self.datasets).start("DATASET-001", "analyst")
        output = InvestigationOrchestrator(self.database, DeterministicMockProvider()).run(investigation["investigation_id"])
        self.proposal_id = output.proposals[0].proposal_id
        self.review = ProposalReviewService(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_policy_validation_and_approval_history(self):
        evaluation = self.review.evaluate(self.proposal_id)
        self.assertTrue(evaluation["policy"]["allowed"])
        self.assertEqual(evaluation["policy"]["code"], "allowed")

        decision = self.review.decide(
            self.proposal_id, reviewer="reviewer-a", decision="approved", comment="Evidence checked"
        )
        self.assertEqual(decision["proposal_status"], "approved")
        history = self.review.history(self.proposal_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["decision"], "approved")
        with self.assertRaises(ProposalDecisionConflict):
            self.review.decide(self.proposal_id, reviewer="reviewer-b", decision="denied")

        with closing(connect(self.database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM execution_records").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM feedback_records").fetchone()[0], 1)
            self.assertGreaterEqual(connection.execute("SELECT count(*) FROM audit_logs").fetchone()[0], 2)

    def test_reviewer_can_modify_then_approve_validated_parameters(self):
        modification = self.review.decide(
            self.proposal_id,
            reviewer="reviewer-a",
            decision="modified",
            action_type="block_ip",
            target_type="ip",
            target_value="192.0.2.90",
            comment="Use the evidenced source IP",
        )
        self.assertEqual(modification["proposal_status"], "policy_validated")
        self.assertTrue(modification["policy"]["allowed"])

        approval = self.review.decide(self.proposal_id, reviewer="reviewer-a", decision="approved")
        self.assertEqual(approval["proposal_status"], "approved")
        history = self.review.history(self.proposal_id)
        self.assertEqual([record["decision"] for record in history], ["modified", "approved"])
        self.assertEqual(history[0]["modified_parameters"]["action_type"], "block_ip")
        self.assertEqual(history[0]["modified_parameters"]["previous_action_type"], "isolate_host")
        self.assertEqual(history[0]["modified_parameters"]["previous_parameters"]["target_value"], "WIN-POLICY-01")

    def test_policy_rejects_unsupported_targets_and_low_severity_actions(self):
        with self.assertRaises(PolicyRejectedError) as invalid_target:
            self.review.decide(
                self.proposal_id,
                reviewer="reviewer-a",
                decision="modified",
                target_type="host",
                target_value="WIN-UNRELATED-01",
            )
        self.assertEqual(invalid_target.exception.result.code, "target_not_evidenced")

        with closing(connect(self.database)) as connection:
            finding_id = connection.execute(
                "SELECT finding_id FROM response_proposals WHERE proposal_id=?", (self.proposal_id,)
            ).fetchone()[0]
            connection.execute("UPDATE agent_findings SET severity='low' WHERE finding_id=?", (finding_id,))
            connection.commit()
        with self.assertRaises(PolicyRejectedError) as low_severity:
            self.review.decide(self.proposal_id, reviewer="reviewer-a", decision="approved")
        self.assertEqual(low_severity.exception.result.code, "severity_below_threshold")

    def test_denial_is_final_and_recorded(self):
        decision = self.review.decide(
            self.proposal_id, reviewer="reviewer-a", decision="denied", comment="Do not isolate"
        )
        self.assertEqual(decision["proposal_status"], "denied")
        self.assertEqual(self.review.history(self.proposal_id)[0]["decision"], "denied")
        with self.assertRaises(ProposalDecisionConflict):
            self.review.decide(self.proposal_id, reviewer="reviewer-a", decision="approved")


if __name__ == "__main__":
    unittest.main()
