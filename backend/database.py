"""SQLite connection and schema initialization."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect(database_path: str | Path) -> sqlite3.Connection:
    """Open a configured SQLite connection with foreign keys and WAL enabled."""
    path = Path(database_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database(database_path: str | Path) -> None:
    """Create all initial tables and indexes; safe to call on every startup."""
    connection = connect(database_path)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    finally:
        connection.close()


@contextmanager
def database_session(database_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Yield a connection and commit on success or roll back on failure."""
    connection = connect(database_path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()
