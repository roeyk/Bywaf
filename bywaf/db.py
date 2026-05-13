"""SQLite event store and pub/sub helpers.

The database is the durable coordination point between commandlets. Commandlets
publish structured events, downstream commandlets subscribe to topics, and the
REPL can inspect the resulting run/pipeline history.
"""

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

sqlcipher: Any
try:
    from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised on systems without the optional extra.
    sqlcipher = None


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

SQLITE_HEADER = b"SQLite format 3\x00"


@dataclass(frozen=True, slots=True)
class Subscription:
    """A scoped request for events newer than a known high-water mark."""

    topics: tuple[str, ...]
    after_id: int = 0
    limit: int = 100
    pipeline_id: str | None = None
    command_run_id: str | None = None
    parent_command_run_id: str | None = None


class EventStore:
    """Thin SQLite wrapper used by the runner and plugins.

    Connections are intentionally short-lived. Each operation opens its own
    autocommit connection, which works well with multiprocessing and avoids
    sharing SQLite connection objects across process boundaries.
    """

    def __init__(self, path: Path | str, *, passphrase: str | None = None):
        self.path = Path(path)
        self.passphrase = passphrase
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a configured SQLite connection.

        WAL mode lets readers and writers coexist better while background
        commandlets are publishing events. The busy timeout gives concurrent
        writers time to finish instead of failing immediately with "database is
        locked".
        """
        driver: Any = sqlite3
        if self.passphrase is not None:
            if sqlcipher is None:
                raise RuntimeError("encrypted databases require the sqlcipher3-binary package")
            driver = sqlcipher
        conn = driver.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = driver.Row
        if self.passphrase is not None:
            set_sqlcipher_key(conn, self.passphrase)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the schema and apply lightweight compatibility migrations."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            ensure_event_columns(conn)

    def checkpoint(self) -> None:
        """Fold WAL contents into the main DB file during clean shutdown."""
        with self.connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def vacuum(self) -> None:
        """Rebuild the active database to reclaim free pages."""
        with self.connect() as conn:
            conn.execute("VACUUM")

    def rekey(self, new_passphrase: str) -> None:
        """Change the SQLCipher passphrase for the active encrypted database."""
        if self.passphrase is None:
            raise ValueError("db rekey requires an encrypted database")
        with self.connect() as conn:
            conn.execute(f"PRAGMA rekey = {sql_literal(new_passphrase)}")
        EventStore(self.path, passphrase=new_passphrase).table_counts()
        self.passphrase = new_passphrase

    @property
    def encrypted(self) -> bool:
        """Return whether this store uses a SQLCipher passphrase."""
        return self.passphrase is not None

    def table_counts(self) -> dict[str, int]:
        """Return row counts for core tables used by `db status`."""
        with self.connect() as conn:
            return {
                "events": int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
                "jobs": int(conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]),
            }

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
        """Insert one event and return it with its SQLite id populated."""
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
        """Return events matching a subscription.

        The topic list is passed as a JSON array and expanded with SQLite's
        `json_each` table-valued function. That keeps the SQL text fixed while
        still supporting a variable number of topics, which avoids both SQL
        injection risk and Bandit false positives.
        """
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
        """Poll until matching events arrive or the timeout expires."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            events = self.fetch(subscription)
            if events or timeout_seconds <= 0 or time.monotonic() >= deadline:
                return events
            time.sleep(interval_seconds)

    def record_job(self, command_line: str, pid: int | None, status: str) -> int:
        """Record a background job owned by the runner."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO jobs(command_line, pid, status, started_at) VALUES (?, ?, ?, ?)",
                (command_line, pid, status, now),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a job row id")
            return int(cursor.lastrowid)

    def finish_job(self, job_id: int, status: str) -> None:
        """Mark a recorded background job as finished or failed."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
                (status, now, job_id),
            )

    def jobs(self) -> list[sqlite3.Row]:
        """Return known jobs with newest jobs first."""
        with self.connect() as conn:
            return list(conn.execute("SELECT * FROM jobs ORDER BY id DESC"))

    def topics(self) -> list[str]:
        """Return distinct event topics currently present in the database."""
        with self.connect() as conn:
            rows = conn.execute("SELECT DISTINCT topic FROM events ORDER BY topic")
            return [row["topic"] for row in rows]

    def events_for_topic(self, topic: str, limit: int = 100) -> list[Event]:
        """Return recent events for one topic."""
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
        """Return events filtered by optional topic/run/pipeline scope.

        Optional predicates are expressed as fixed nullable SQL predicates so no
        SQL text is assembled from user-controlled values.
        """
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
        """Summarize commandlet executions that produced events."""
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
    """Add scope columns when opening a DB created by an older build."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    for name in ("pipeline_id", "command_run_id", "parent_command_run_id"):
        if name not in columns:
            conn.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")


def set_sqlcipher_key(conn: Any, passphrase: str) -> None:
    """Apply a SQLCipher key to a new connection.

    SQLCipher's PRAGMA syntax does not accept DB-API placeholders on all builds,
    so the passphrase is escaped as a SQL string literal before being embedded.
    """
    conn.execute(f"PRAGMA key = {sql_literal(passphrase)}")
    conn.execute("SELECT count(*) FROM sqlite_master")


def sql_literal(value: str) -> str:
    """Return `value` as a single-quoted SQL literal."""
    return "'" + value.replace("'", "''") + "'"


def database_appears_encrypted(path: Path | str) -> bool:
    """Return True when an existing DB does not have the plaintext SQLite header."""
    db_path = Path(path)
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    with db_path.open("rb") as handle:
        return handle.read(len(SQLITE_HEADER)) != SQLITE_HEADER


def sqlcipher_available() -> bool:
    """Return whether the optional SQLCipher DB-API driver is importable."""
    return sqlcipher is not None


def export_encrypted_database(
    source: Path | str,
    destination: Path | str,
    passphrase: str,
    *,
    source_passphrase: str | None = None,
) -> None:
    """Export a SQLite database to an encrypted SQLCipher database."""
    if sqlcipher is None:
        raise RuntimeError("encrypted database export requires the sqlcipher3-binary package")
    export_sqlcipher_database(source, destination, passphrase, source_passphrase=source_passphrase)


def export_plaintext_database(
    source: Path | str,
    destination: Path | str,
    *,
    source_passphrase: str,
) -> None:
    """Export an encrypted SQLCipher database to plaintext SQLite."""
    if sqlcipher is None:
        raise RuntimeError("plaintext database export requires the sqlcipher3-binary package")
    export_sqlcipher_database(source, destination, "", source_passphrase=source_passphrase)


def export_sqlcipher_database(
    source: Path | str,
    destination: Path | str,
    destination_passphrase: str,
    *,
    source_passphrase: str | None = None,
) -> None:
    """Export from a SQLCipher-readable source to a destination database."""
    if sqlcipher is None:
        raise RuntimeError("database export requires the sqlcipher3-binary package")
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists():
        destination_path.unlink()
    with sqlcipher.connect(str(source_path), isolation_level=None) as conn:
        if source_passphrase is not None:
            set_sqlcipher_key(conn, source_passphrase)
        conn.execute(
            f"ATTACH DATABASE {sql_literal(str(destination_path))} AS exported "
            f"KEY {sql_literal(destination_passphrase)}"
        )
        conn.execute("SELECT sqlcipher_export('exported')")
        conn.execute("DETACH DATABASE exported")
