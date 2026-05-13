"""SQLite schema and compatibility migrations."""

from __future__ import annotations

import sqlite3


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    pipeline_id TEXT,
    command_run_id TEXT,
    parent_command_run_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_topic_id ON events(topic, id);
CREATE INDEX IF NOT EXISTS idx_events_scope ON events(topic, pipeline_id, command_run_id, id);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_line TEXT NOT NULL,
    pid INTEGER,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS cancellations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason TEXT,
    requested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cancellations_target ON cancellations(target_type, target_id);

CREATE TABLE IF NOT EXISTS command_run_vars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER,
    pipeline_id TEXT NOT NULL,
    command_run_id TEXT NOT NULL,
    commandlet TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(command_run_id, name)
);
CREATE INDEX IF NOT EXISTS idx_command_run_vars_run ON command_run_vars(command_run_id, name);
"""


def ensure_event_columns(conn: sqlite3.Connection) -> None:
    """Add tables/columns when opening a DB created by an older build."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for name in ("pipeline_id", "command_run_id", "parent_command_run_id"):
        if name not in columns:
            conn.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
    tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "cancellations" not in tables:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cancellations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT,
                requested_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cancellations_target
            ON cancellations(target_type, target_id);
            """
        )
    if "command_run_vars" not in tables:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS command_run_vars (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                pipeline_id TEXT NOT NULL,
                command_run_id TEXT NOT NULL,
                commandlet TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(command_run_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_command_run_vars_run
            ON command_run_vars(command_run_id, name);
            """
        )
