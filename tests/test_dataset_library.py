"""Tests for generated dataset structure, provenance, and checksums."""

import hashlib
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from scripts.generate_synthetic_datasets import generate_library


class DatasetLibraryTests(unittest.TestCase):
    def test_library_is_selectable_normalized_and_checksummed(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp_dir:
            root = Path(temp_dir)
            index = generate_library(root, events_per_dataset=100)

            self.assertEqual(index["dataset_count"], 3)
            self.assertEqual(index["total_event_count"], 300)
            self.assertEqual(index["severity_counts"], {
                "critical": 15, "high": 30, "informational": 75, "low": 105, "medium": 75
            })
            for dataset in index["datasets"]:
                dataset_dir = root / dataset["dataset_id"]
                manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
                event_bytes = (dataset_dir / "events.jsonl").read_bytes()
                truth_bytes = (dataset_dir / "ground_truth.jsonl").read_bytes()
                self.assertEqual(hashlib.sha256(event_bytes).hexdigest(), manifest["event_file_sha256"])
                self.assertEqual(hashlib.sha256(truth_bytes).hexdigest(), manifest["ground_truth_file_sha256"])

                events = [json.loads(line) for line in event_bytes.splitlines()]
                truths = [json.loads(line) for line in truth_bytes.splitlines()]
                self.assertEqual(len(events), 100)
                self.assertEqual(len(truths), 100)
                self.assertEqual(len({event["event_id"] for event in events}), 100)
                self.assertEqual({event["source"]["origin"] for event in events}, {"synthetic"})
                self.assertNotIn("ground_truth", events[0])
                self.assertEqual({event["source"]["type"] for event in events}, set(manifest["source_types"]))
                self.assertEqual(Counter(event["event"]["severity"] for event in events), Counter(manifest["severity_counts"]))


if __name__ == "__main__":
    unittest.main()
