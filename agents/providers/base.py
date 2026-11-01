"""Provider-independent contract for structured agent completions."""

from __future__ import annotations

from typing import Any, Protocol


class AgentProvider(Protocol):
    def complete(self, *, task: str, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        """Return a structured completion for a named task."""
