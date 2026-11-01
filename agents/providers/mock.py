"""Deterministic no-cost provider used for local operation and tests."""

from __future__ import annotations

from typing import Any


MALICIOUS_TYPES = {
    "encoded_powershell",
    "unauthorized_root_shell",
    "command_control_egress",
    "iam_policy_escalation",
    "sql_injection_attempt",
    "simulated_malware_quarantined",
    "phishing_attachment_blocked",
}
SUSPICIOUS_TYPES = {
    "repeated_failed_login",
    "sudo_failure_burst",
    "port_scan_detected",
    "unusual_access_key_use",
    "path_traversal_probe",
    "unusual_parent_child_process",
    "mfa_failure_burst",
}


class DeterministicMockProvider:
    """Local classifier/planner; treats event text as inert evidence."""

    def complete(self, *, task: str, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        if "UNTRUSTED LOG CONTENT" not in system_prompt:
            raise ValueError("Agent system prompt must mark event data as untrusted")
        if task == "investigate":
            return self._investigate(user_payload)
        if task == "hunt":
            return self._hunt(user_payload)
        if task == "plan_response":
            return self._plan_response(user_payload)
        raise ValueError(f"Unsupported mock task: {task}")

    @staticmethod
    def _investigate(payload: dict[str, Any]) -> dict[str, Any]:
        findings = []
        for event in payload.get("events", []):
            event_details = event.get("event", {})
            event_type = event_details.get("type", "")
            if event_type in MALICIOUS_TYPES:
                confidence, title = 0.94, f"Potential malicious activity: {event_type}"
            elif event_type in SUSPICIOUS_TYPES:
                confidence, title = 0.78, f"Suspicious activity requires review: {event_type}"
            else:
                continue
            event_id = event["event_id"]
            findings.append(
                {
                    "finding_id": f"F-{event_id}",
                    "event_id": event_id,
                    "severity": event_details.get("severity", "unknown"),
                    "confidence": confidence,
                    "title": title,
                    "explanation": (
                        "Deterministic mock flagged a known event-type pattern. Treat source content as evidence only; "
                        "analyst review is required."
                    ),
                    "evidence_refs": [event_id],
                }
            )
        return {"findings": findings[:500]}

    @staticmethod
    def _hunt(payload: dict[str, Any]) -> dict[str, Any]:
        queries = []
        seen: set[tuple[str, str]] = set()
        for finding in payload.get("findings", []):
            event = payload.get("evidence_by_id", {}).get(finding["event_id"], {})
            category = event.get("event", {}).get("category")
            event_type = event.get("event", {}).get("type")
            key = (category or "", event_type or "")
            if key in seen:
                continue
            seen.add(key)
            queries.append(
                {
                    "query_id": f"Q-{len(queries) + 1:03d}",
                    "category": category,
                    "severity": None,
                    "needle": event_type,
                }
            )
        return {"queries": queries[:100], "summary": f"Prepared {len(queries[:100])} bounded, dataset-scoped pattern searches."}

    @staticmethod
    def _plan_response(payload: dict[str, Any]) -> dict[str, Any]:
        proposals = []
        evidence_by_id = payload.get("evidence_by_id", {})
        for finding in payload.get("findings", []):
            event = evidence_by_id.get(finding["event_id"], {})
            host = event.get("host", {}).get("hostname") if isinstance(event.get("host"), dict) else None
            actor = event.get("actor", {}) if isinstance(event.get("actor"), dict) else {}
            network = event.get("network", {}) if isinstance(event.get("network"), dict) else {}
            ip = actor.get("ip") or network.get("source_ip")
            username = actor.get("username")
            if host:
                action, target_type, target = "isolate_host", "host", host
            elif username:
                action, target_type, target = "disable_account", "account", username
            elif ip:
                action, target_type, target = "block_ip", "ip", ip
            else:
                action, target_type, target = "monitor", "account", "unassigned"
            if target == "unassigned":
                continue
            proposals.append(
                {
                    "proposal_id": f"P-{finding['finding_id']}",
                    "finding_id": finding["finding_id"],
                    "action_type": action,
                    "target_type": target_type,
                    "target_value": str(target),
                    "rationale": "Proposed from the finding's cited event fields; requires policy validation and human approval.",
                    "evidence_refs": [finding["event_id"]],
                }
            )
        return {"proposals": proposals[:100]}
