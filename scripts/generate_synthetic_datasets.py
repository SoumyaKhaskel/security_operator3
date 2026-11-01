"""Generate a reproducible, synthetic security event library."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
GENERATED_AT = "2026-10-31T00:00:00Z"
DATASETS = (
    ("DATASET-001", "Northstar Enterprise", 1103),
    ("DATASET-002", "Harbor Cloud and Identity", 2207),
    ("DATASET-003", "Cedar Mixed Operations", 3301),
)
SEVERITIES = ("critical", "high", "medium", "low", "informational")
SEVERITY_CYCLE = (
    ["critical"]
    + ["high"] * 2
    + ["medium"] * 5
    + ["low"] * 7
    + ["informational"] * 5
)
LABEL_CYCLE = (
    ["benign"] * 68
    + ["suspicious"] * 14
    + ["malicious"] * 10
    + ["false_positive"] * 8
)

SOURCES = (
    {
        "type": "windows_security",
        "product": "Windows Security (simulated)",
        "hostname": "WIN-SERVER-01",
        "os": "Windows Server 2022 (simulated)",
        "normal": ("successful_login", "Interactive logon completed for a standard account"),
        "suspicious": ("repeated_failed_login", "Repeated failed logons from an unfamiliar internal address"),
        "malicious": ("encoded_powershell", "Encoded PowerShell launched by an unexpected parent process"),
        "false_positive": ("blocked_admin_tool", "Administrative script blocked during an approved maintenance window"),
        "tactic": "Credential Access",
        "technique": "T1110",
    },
    {
        "type": "linux_auth",
        "product": "Linux auth and audit (simulated)",
        "hostname": "LINUX-SERVER-01",
        "os": "Ubuntu Server 24.04 (simulated)",
        "normal": ("ssh_login_success", "SSH session opened for a named operations account"),
        "suspicious": ("sudo_failure_burst", "Several sudo authentication failures were recorded"),
        "malicious": ("unauthorized_root_shell", "Root shell opened after an untrusted script execution"),
        "false_positive": ("approved_cron_change", "Cron entry changed by the approved configuration manager"),
        "tactic": "Privilege Escalation",
        "technique": "T1548",
    },
    {
        "type": "network_firewall",
        "product": "Network Firewall and IDS (simulated)",
        "hostname": "FIREWALL-01",
        "os": "Network appliance (simulated)",
        "normal": ("connection_allowed", "Expected application traffic was allowed by policy"),
        "suspicious": ("port_scan_detected", "A short connection burst touched multiple destination ports"),
        "malicious": ("command_control_egress", "Outbound connection matched a simulated command-and-control rule"),
        "false_positive": ("blocked_vulnerability_scan", "Approved internal scanner traffic was blocked at the perimeter"),
        "tactic": "Command and Control",
        "technique": "T1071",
    },
    {
        "type": "cloud_audit",
        "product": "CloudTrail and Activity (simulated)",
        "hostname": "AWS-ACCOUNT-01",
        "os": "Cloud control plane (simulated)",
        "normal": ("read_only_api_call", "Read-only inventory API call completed successfully"),
        "suspicious": ("unusual_access_key_use", "Access key was used from an unusual simulated region"),
        "malicious": ("iam_policy_escalation", "Unexpected policy change granted broad privileges to a test role"),
        "false_positive": ("approved_security_group_change", "Security group update matched an approved change record"),
        "tactic": "Privilege Escalation",
        "technique": "T1098",
    },
    {
        "type": "web_application",
        "product": "Web Application Gateway (simulated)",
        "hostname": "WEB-APP-01",
        "os": "Linux container host (simulated)",
        "normal": ("http_request", "Routine authenticated request returned a successful response"),
        "suspicious": ("path_traversal_probe", "Request contained a path traversal test pattern"),
        "malicious": ("sql_injection_attempt", "Request matched a simulated SQL injection exploit pattern"),
        "false_positive": ("escaped_input_match", "Security rule matched a safely escaped search string"),
        "tactic": "Initial Access",
        "technique": "T1190",
    },
    {
        "type": "endpoint_security",
        "product": "Endpoint Protection (simulated)",
        "hostname": "WIN-WORKSTATION-01",
        "os": "Windows 11 (simulated)",
        "normal": ("process_started", "Signed productivity application started normally"),
        "suspicious": ("unusual_parent_child_process", "Office application spawned an uncommon script interpreter"),
        "malicious": ("simulated_malware_quarantined", "Test malware artifact was detected and quarantined"),
        "false_positive": ("developer_tool_detection", "Approved developer utility matched a generic behavior rule"),
        "tactic": "Execution",
        "technique": "T1059",
    },
    {
        "type": "email_identity",
        "product": "Mail and Identity Protection (simulated)",
        "hostname": "MAIL-SERVER-01",
        "os": "Managed mail service (simulated)",
        "normal": ("mfa_success", "MFA challenge succeeded for a known user and device"),
        "suspicious": ("mfa_failure_burst", "Several MFA challenges failed for one test identity"),
        "malicious": ("phishing_attachment_blocked", "Simulated phishing attachment was blocked before delivery"),
        "false_positive": ("travel_alert_cleared", "Travel anomaly was cleared after a known VPN change"),
        "tactic": "Credential Access",
        "technique": "T1566",
    },
)

HOST_SUFFIXES = ("01", "02", "03", "04")
USERS = ("analyst", "svc_backup", "j.smith", "build-agent", "admin-test", "mail-user")
TEST_IPS = ("192.0.2.10", "198.51.100.24", "203.0.113.77", "192.0.2.201")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_write(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            stream.write("\n")


def _make_event(dataset_id: str, index: int, rng: random.Random) -> tuple[dict[str, Any], dict[str, str]]:
    source = SOURCES[(index - 1) % len(SOURCES)]
    label = LABEL_CYCLE[(index - 1) % len(LABEL_CYCLE)]
    severity = SEVERITY_CYCLE[(index - 1) % len(SEVERITY_CYCLE)]
    scenario_key = {"benign": "normal"}.get(label, label)
    event_type, message = source[scenario_key]
    event_time = datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(
        seconds=(index - 1) * 37 + rng.randrange(0, 30)
    )
    ingested_at = event_time + timedelta(seconds=rng.randrange(1, 300))
    actor_ip = rng.choice(TEST_IPS)
    username = rng.choice(USERS)
    event_id = f"{dataset_id}-EVT-{index:06d}"
    category = source["type"]

    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "dataset_id": dataset_id,
        "event_time": event_time.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ingested_at": ingested_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source": {
            "type": category,
            "format": "jsonl",
            "origin": "synthetic",
            "product": source["product"],
        },
        "host": {"hostname": source["hostname"], "os": source["os"]},
        "event": {
            "category": category,
            "type": event_type,
            "action": event_type,
            "outcome": "failure" if label == "suspicious" else "success",
            "severity": severity,
        },
        "actor": {"username": username, "ip": actor_ip},
        "target": {"username": rng.choice(USERS)},
        "network": {
            "source_ip": actor_ip,
            "destination_ip": rng.choice(TEST_IPS),
            "destination_port": rng.choice((22, 53, 443, 445, 3389, 8080)),
            "protocol": rng.choice(("TCP", "UDP")),
        },
        "threat": {
            "tactic": source["tactic"] if label in {"suspicious", "malicious"} else None,
            "technique_id": source["technique"] if label in {"suspicious", "malicious"} else None,
            "indicators": [event_type] if label == "malicious" else [],
        },
        "message": message,
        "raw_event": {
            "source_record_id": f"SIM-{dataset_id[-3:]}-{index:06d}",
            "simulation": True,
            "note": "Generated synthetic training event; not collected from a real system.",
        },
        "labels": [category, "synthetic"],
        "status": "uninvestigated",
    }
    ground_truth = {
        "event_id": event_id,
        "label": label,
        "source": "synthetic_generator_v1",
    }
    return event, ground_truth


def generate_library(output_dir: Path, events_per_dataset: int = 2000) -> dict[str, Any]:
    """Write three selectable datasets with separately stored evaluation labels."""
    if events_per_dataset < len(SEVERITY_CYCLE) or events_per_dataset % len(SEVERITY_CYCLE):
        raise ValueError(f"events_per_dataset must be a multiple of {len(SEVERITY_CYCLE)}")

    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_entries = []
    total_severity: Counter[str] = Counter()

    for dataset_id, name, seed in DATASETS:
        dataset_dir = output_dir / dataset_id
        dataset_dir.mkdir(parents=True, exist_ok=True)
        rng = random.Random(seed)
        events: list[dict[str, Any]] = []
        ground_truth: list[dict[str, str]] = []
        for index in range(1, events_per_dataset + 1):
            event, truth = _make_event(dataset_id, index, rng)
            events.append(event)
            ground_truth.append(truth)

        event_counts = Counter(event["event"]["severity"] for event in events)
        total_severity.update(event_counts)
        event_path = dataset_dir / "events.jsonl"
        truth_path = dataset_dir / "ground_truth.jsonl"
        _jsonl_write(event_path, events)
        _jsonl_write(truth_path, ground_truth)

        manifest = {
            "manifest_version": "1.0",
            "dataset_id": dataset_id,
            "name": name,
            "description": "Synthetic multi-source security events for local investigation and evaluation.",
            "provenance": {
                "origin": "synthetic",
                "generator": "scripts/generate_synthetic_datasets.py",
                "generator_version": "1.0",
                "generated_at": GENERATED_AT,
                "public_dataset_content": False,
            },
            "event_count": events_per_dataset,
            "event_file": "events.jsonl",
            "event_file_sha256": _sha256(event_path),
            "ground_truth_file": "ground_truth.jsonl",
            "ground_truth_file_sha256": _sha256(truth_path),
            "ground_truth_access": "evaluation_only; do not provide to investigation agents",
            "severity_counts": dict(sorted(event_counts.items())),
            "source_types": [item["type"] for item in SOURCES],
        }
        (dataset_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        dataset_entries.append(
            {
                "dataset_id": dataset_id,
                "name": name,
                "manifest": f"{dataset_id}/manifest.json",
                "event_count": events_per_dataset,
                "provenance": "synthetic",
            }
        )

    index = {
        "library_version": "1.0",
        "generated_at": GENERATED_AT,
        "dataset_count": len(dataset_entries),
        "total_event_count": events_per_dataset * len(DATASETS),
        "severity_counts": dict(sorted(total_severity.items())),
        "datasets": dataset_entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "datasets",
        help="Directory where the synthetic library will be written.",
    )
    parser.add_argument("--events-per-dataset", type=int, default=2000)
    args = parser.parse_args()
    index = generate_library(args.output_dir, args.events_per_dataset)
    print(f"Generated {index['total_event_count']} events across {index['dataset_count']} datasets at {args.output_dir}")


if __name__ == "__main__":
    main()
