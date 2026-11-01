"""Deterministic policy checks for evidence-backed proposed actions."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any


ALLOWED_ACTIONS = {"isolate_host", "disable_account", "block_ip", "monitor"}
HIGH_IMPACT_ACTIONS = {"isolate_host", "disable_account", "block_ip"}


@dataclass(frozen=True, slots=True)
class PolicyResult:
    allowed: bool
    code: str
    reason: str
    policy_version: str = "1.0"


class PolicyEngine:
    """Require approved action, verified evidence target, and sufficient confidence."""

    def evaluate(
        self,
        *,
        action_type: str,
        parameters: dict[str, Any],
        finding: dict[str, Any],
        evidence_event: dict[str, Any],
    ) -> PolicyResult:
        if action_type not in ALLOWED_ACTIONS:
            return PolicyResult(False, "action_not_allowed", "Action is not in the simulation policy allowlist.")
        if not isinstance(parameters, dict) or set(parameters) != {"target_type", "target_value"}:
            return PolicyResult(False, "invalid_parameters", "Parameters must contain only target_type and target_value.")

        target_type = parameters.get("target_type")
        target_value = parameters.get("target_value")
        if not isinstance(target_value, str) or not target_value.strip() or len(target_value) > 256:
            return PolicyResult(False, "invalid_target", "A concrete target value is required.")
        if target_value.strip() in {"*", "any", "all", "unassigned"}:
            return PolicyResult(False, "broad_target", "Wildcard or unassigned targets are not allowed.")

        event_host = evidence_event.get("host") if isinstance(evidence_event.get("host"), dict) else {}
        actor = evidence_event.get("actor") if isinstance(evidence_event.get("actor"), dict) else {}
        target = evidence_event.get("target") if isinstance(evidence_event.get("target"), dict) else {}
        network = evidence_event.get("network") if isinstance(evidence_event.get("network"), dict) else {}
        target_matches = False
        if action_type == "isolate_host" and target_type == "host":
            target_matches = event_host.get("hostname") == target_value
        elif action_type == "disable_account" and target_type == "account":
            target_matches = target_value in {actor.get("username"), target.get("username")}
        elif action_type == "block_ip" and target_type == "ip":
            evidence_ips = {actor.get("ip"), network.get("source_ip"), network.get("destination_ip")}
            try:
                ipaddress.ip_address(target_value)
                target_matches = target_value in evidence_ips
            except ValueError:
                target_matches = False
        elif action_type == "monitor":
            target_matches = (
                target_type == "host" and event_host.get("hostname") == target_value
                or target_type == "account" and target_value in {actor.get("username"), target.get("username")}
                or target_type == "ip" and target_value in {actor.get("ip"), network.get("source_ip"), network.get("destination_ip")}
            )
        if not target_matches:
            return PolicyResult(False, "target_not_evidenced", "Target does not match the cited original event fields.")

        if action_type in HIGH_IMPACT_ACTIONS:
            if finding.get("severity") not in {"critical", "high"}:
                return PolicyResult(False, "severity_below_threshold", "High-impact simulated actions require a high or critical finding.")
            if float(finding.get("confidence", 0)) < 0.75:
                return PolicyResult(False, "confidence_below_threshold", "High-impact simulated actions require confidence of at least 0.75.")
        return PolicyResult(True, "allowed", "Proposal satisfies policy and evidence checks.")
