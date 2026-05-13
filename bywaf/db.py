"""SQLite event store and pub/sub helpers."""

from __future__ import annotations

import sqlite3
import time
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .events import Event


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
"""


@dataclass(frozen=True, slots=True)
class Subscription:
    topics: tuple[str, ...]
    after_id: int = 0
    limit: int = 100
    pipeline_id: str | None = None
    command_run_id: str | None = None
    parent_command_run_id: str | None = None


class EventStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            ensure_event_columns(conn)

    def checkpoint(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        source: str,
        *,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> Event:
        event = Event.new(
            topic,
            payload,
            source,
            pipeline_id=pipeline_id,
            command_run_id=command_run_id,
            parent_command_run_id=parent_command_run_id,
        )
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events(
                    topic,
                    payload_json,
                    source,
                    created_at,
                    pipeline_id,
                    command_run_id,
                    parent_command_run_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.topic,
                    event.payload_json(),
                    event.source,
                    event.created_at.isoformat(),
                    event.pipeline_id,
                    event.command_run_id,
                    event.parent_command_run_id,
                ),
            )
            return Event(
                cursor.lastrowid,
                event.topic,
                event.payload,
                event.source,
                event.created_at,
                event.pipeline_id,
                event.command_run_id,
                event.parent_command_run_id,
            )

    def fetch(self, subscription: Subscription) -> list[Event]:
        if not subscription.topics:
            return []
        sql = """
            SELECT * FROM events
            WHERE id > ?
              AND topic IN (SELECT value FROM json_each(?))
              AND (? IS NULL OR pipeline_id = ?)
              AND (? IS NULL OR command_run_id = ?)
              AND (? IS NULL OR parent_command_run_id = ?)
            ORDER BY id ASC
            LIMIT ?
        """
        params: list[Any] = [
            subscription.after_id,
            json.dumps(subscription.topics),
            subscription.pipeline_id,
            subscription.pipeline_id,
            subscription.command_run_id,
            subscription.command_run_id,
            subscription.parent_command_run_id,
            subscription.parent_command_run_id,
            subscription.limit,
        ]
        with self.connect() as conn:
            return [Event.from_row(row) for row in conn.execute(sql, tuple(params))]

    def poll(
        self,
        subscription: Subscription,
        *,
        timeout_seconds: float = 0,
        interval_seconds: float = 0.25,
    ) -> list[Event]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            events = self.fetch(subscription)
            if events or timeout_seconds <= 0 or time.monotonic() >= deadline:
                return events
            time.sleep(interval_seconds)

    def record_job(self, command_line: str, pid: int | None, status: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO jobs(command_line, pid, status, started_at) VALUES (?, ?, ?, ?)",
                (command_line, pid, status, now),
            )
            return int(cursor.lastrowid)

    def finish_job(self, job_id: int, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
                (status, now, job_id),
            )

    def jobs(self) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(conn.execute("SELECT * FROM jobs ORDER BY id DESC"))

    def topics(self) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT DISTINCT topic FROM events ORDER BY topic")
            return [row["topic"] for row in rows]

    def events_for_topic(self, topic: str, limit: int = 100) -> list[Event]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE topic = ? ORDER BY id ASC LIMIT ?",
                (topic, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE (? IS NULL OR topic = ?)
                  AND (? IS NULL OR command_run_id = ?)
                  AND (? IS NULL OR pipeline_id = ?)
                ORDER BY id ASC
                LIMIT ?
                """,
                (topic, topic, command_run_id, command_run_id, pipeline_id, pipeline_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def runs(self) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT
                        command_run_id,
                        pipeline_id,
                        source,
                        COUNT(*) AS events,
                        MIN(created_at) AS first_event,
                        MAX(created_at) AS last_event
                    FROM events
                    WHERE command_run_id IS NOT NULL
                    GROUP BY command_run_id, pipeline_id, source
                    ORDER BY MAX(id) DESC
                    """
                )
            )


def ensure_event_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for name in ("pipeline_id", "command_run_id", "parent_command_run_id"):
        if name not in columns:
            conn.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
