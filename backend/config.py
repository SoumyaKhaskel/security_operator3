"""Environment-based application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path
    log_level: str
    llm_provider: str
    llm_api_key: str | None


def get_settings() -> Settings:
    """Load settings without requiring a dotenv library or external service."""
    api_key = os.getenv("SOP_LLM_API_KEY", "").strip() or None
    return Settings(
        database_path=Path(os.getenv("SOP_DATABASE_PATH", "data/database/security_operations.db")),
        log_level=os.getenv("SOP_LOG_LEVEL", "INFO").upper(),
        llm_provider=os.getenv("SOP_LLM_PROVIDER", "mock").lower(),
        llm_api_key=api_key,
    )
