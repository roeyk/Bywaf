"""SQLite schema definition and compatibility migrations.

Provides the canonical schema SQL plus lightweight migration helpers for columns
that may be missing in older Bywaf databases.

Used by:
- EventStore initialization: creates and upgrades database files.
- database tests: verify backward-compatible schema evolution."""


from __future__ import annotations

import sqlite3
from typing import Any


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
    serial TEXT UNIQUE,
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

CREATE TABLE IF NOT EXISTS runtime_entities (
    entity_type TEXT NOT NULL,
    local_id INTEGER NOT NULL,
    serial TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(entity_type, serial),
    UNIQUE(entity_type, local_id)
);
CREATE INDEX IF NOT EXISTS idx_runtime_entities_serial ON runtime_entities(serial);

CREATE TABLE IF NOT EXISTS secrets (
    ref TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);

CREATE TABLE IF NOT EXISTS trigger_state (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL DEFAULT 0,
    last_fired_event_id INTEGER,
    updated_at TEXT NOT NULL
);
"""


def ensure_event_columns(conn: sqlite3.Connection | Any) -> None:
    """Add tables/columns when opening a DB created by an older build."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for name in ("pipeline_id", "command_run_id", "parent_command_run_id"):
        if name not in columns:
            # Scope columns were added after the initial event table. Add them
            # lazily so existing project databases remain readable.
            conn.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
    job_columns = {row["name"] for row in conn.execute("PRAGMA table_info(jobs)")}
    if "serial" not in job_columns:
        conn.execute("ALTER TABLE jobs ADD COLUMN serial TEXT")
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
        # Variable snapshots are evidence: they capture the effective settings
        # for a pipeline step without relying on mutable session config.
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
    if "runtime_entities" not in tables:
        # Runtime entities give durable serials stable local IDs for display.
        # They are derived metadata, not the source of pipeline/job truth.
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runtime_entities (
                entity_type TEXT NOT NULL,
                local_id INTEGER NOT NULL,
                serial TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(entity_type, serial),
                UNIQUE(entity_type, local_id)
            );
            CREATE INDEX IF NOT EXISTS idx_runtime_entities_serial
            ON runtime_entities(serial);
            """
        )
    if "secrets" not in tables:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                ref TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
            """
        )
    if "trigger_state" not in tables:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS trigger_state (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                last_event_id INTEGER NOT NULL DEFAULT 0,
                last_fired_event_id INTEGER,
                updated_at TEXT NOT NULL
            );
            """
        )
