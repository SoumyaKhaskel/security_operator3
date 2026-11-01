"""Provider implementations for agent completions."""

from agents.providers.mock import DeterministicMockProvider


def configured_provider(provider_name: str = "mock"):
    if provider_name != "mock":
        raise ValueError(f"LLM provider '{provider_name}' is not implemented; configure 'mock'")
    return DeterministicMockProvider()
