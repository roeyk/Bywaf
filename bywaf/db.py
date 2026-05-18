"""SQLite event store and pub/sub helpers.

The database is the durable coordination point between commandlets. Commandlets
publish structured events, downstream commandlets subscribe to topics, and the
REPL can inspect the resulting run/pipeline history.
"""

from __future__ import annotations

import sqlite3
import time
import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db_schema import SCHEMA, ensure_event_columns
from .events import Event

sqlcipher: Any
try:
    from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised on systems without the optional extra.
    sqlcipher = None

SQLITE_HEADER = b"SQLite format 3\x00"
ACTIVE_JOB_STATUSES = ("queued", "claimed", "running", "pausing", "paused", "cancelling")


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
        saved: Event
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
            saved = Event(
                cursor.lastrowid,
                event.topic,
                event.payload,
                event.source,
                event.created_at,
                event.pipeline_id,
                event.command_run_id,
                event.parent_command_run_id,
            )
        if saved.pipeline_id:
            self.ensure_runtime_entity("pipeline", saved.pipeline_id, saved.created_at.isoformat())
        if saved.command_run_id:
            self.ensure_runtime_entity("run", saved.command_run_id, saved.created_at.isoformat())
        return saved

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
        serial = new_serial("job")
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO jobs(serial, command_line, pid, status, started_at) VALUES (?, ?, ?, ?, ?)",
                (serial, command_line, pid, status, now),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a job row id")
            return int(cursor.lastrowid)

    def update_job_pid(self, job_id: int, pid: int | None) -> None:
        """Attach a child PID to an already-created job row."""
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET pid = ? WHERE id = ?", (pid, job_id))

    def claim_job(self, job_id: int, pid: int | None) -> bool:
        """Atomically claim a queued job for one worker process."""
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE jobs
                SET status = 'claimed', pid = ?
                WHERE id = ? AND status = 'queued'
                """,
                (pid, job_id),
            )
            return cursor.rowcount == 1

    def finish_job(self, job_id: int, status: str) -> None:
        """Mark a recorded background job as finished or failed."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
                (status, now, job_id),
            )

    def update_job_status(self, job_id: int, status: str) -> None:
        """Update a job status without marking it finished."""
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET status = ? WHERE id = ?", (status, job_id))

    def jobs(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Return known jobs with newest jobs first."""
        self.ensure_job_serials()
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT *
                    FROM jobs
                    WHERE ? = 0 OR status IN (?, ?, ?, ?, ?, ?)
                    ORDER BY id DESC
                    """,
                    (1 if active_only else 0, *ACTIVE_JOB_STATUSES),
                )
            )

    def mark_stale_jobs(self) -> int:
        """Mark active jobs stale when their recorded process is gone."""
        stale_ids: list[int] = []
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, pid FROM jobs WHERE status IN (?, ?, ?, ?, ?, ?)",
                ACTIVE_JOB_STATUSES,
            ).fetchall()
            for row in rows:
                pid = row["pid"]
                if pid is None or not process_exists(int(pid)):
                    stale_ids.append(int(row["id"]))
            now = datetime.now(timezone.utc).isoformat()
            for job_id in stale_ids:
                conn.execute(
                    "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
                    ("stale", now, job_id),
                )
        return len(stale_ids)

    def job(self, job_id: int) -> sqlite3.Row | None:
        """Return one job row by ID."""
        self.ensure_job_serials()
        with self.connect() as conn:
            return conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()

    def job_serial(self, job_id: int | str) -> str | None:
        """Return a durable job serial for a local job id."""
        self.ensure_job_serials()
        with self.connect() as conn:
            row = conn.execute("SELECT serial FROM jobs WHERE id = ?", (int(job_id),)).fetchone()
            return str(row["serial"]) if row is not None and row["serial"] is not None else None

    def ensure_job_serials(self) -> None:
        """Backfill durable serials for jobs created before job serial support."""
        with self.connect() as conn:
            rows = conn.execute("SELECT id FROM jobs WHERE serial IS NULL ORDER BY id").fetchall()
            for row in rows:
                conn.execute("UPDATE jobs SET serial = ? WHERE id = ?", (new_serial("job"), int(row["id"])))

    def jobs_for_pipeline(self, pipeline_id: str) -> list[sqlite3.Row]:
        """Return jobs associated with a command-run variable snapshot pipeline."""
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT DISTINCT jobs.*
                    FROM command_run_vars
                    JOIN jobs ON jobs.id = command_run_vars.job_id
                    WHERE command_run_vars.pipeline_id = ?
                      AND command_run_vars.job_id IS NOT NULL
                    ORDER BY jobs.id
                    """,
                    (pipeline_id,),
                )
            )

    def jobs_for_run(self, command_run_id: str) -> list[sqlite3.Row]:
        """Return jobs associated with one command-run variable snapshot."""
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT DISTINCT jobs.*
                    FROM command_run_vars
                    JOIN jobs ON jobs.id = command_run_vars.job_id
                    WHERE command_run_vars.command_run_id = ?
                      AND command_run_vars.job_id IS NOT NULL
                    ORDER BY jobs.id
                    """,
                    (command_run_id,),
                )
            )

    def request_cancellation(self, target_type: str, target_id: str, reason: str | None = None) -> None:
        """Record a soft-cancellation request for a job, pipeline, or run."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO cancellations(target_type, target_id, reason, requested_at)
                VALUES (?, ?, ?, ?)
                """,
                (target_type, target_id, reason, now),
            )

    def cancellation_requested(
        self,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> bool:
        """Return whether any matching soft-cancellation request exists."""
        targets: list[tuple[str, str]] = []
        if job_id is not None:
            targets.append(("job", str(job_id)))
        if pipeline_id:
            targets.append(("pipeline", pipeline_id))
        if command_run_id:
            targets.append(("run", command_run_id))
        if not targets:
            return False
        with self.connect() as conn:
            for target_type, target_id in targets:
                row = conn.execute(
                    "SELECT 1 FROM cancellations WHERE target_type = ? AND target_id = ? LIMIT 1",
                    (target_type, target_id),
                ).fetchone()
                if row is not None:
                    return True
        return False

    def record_command_run_vars(
        self,
        *,
        job_id: int | None,
        pipeline_id: str,
        command_run_id: str,
        commandlet: str,
        values: dict[str, str],
        source: str = "snapshot",
    ) -> None:
        """Persist the effective variables captured for one command run."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO command_run_vars(
                    job_id,
                    pipeline_id,
                    command_run_id,
                    commandlet,
                    name,
                    value,
                    source,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (job_id, pipeline_id, command_run_id, commandlet, name, value, source, now)
                    for name, value in sorted(values.items())
                ],
            )
        self.ensure_runtime_entity("pipeline", pipeline_id, now)
        self.ensure_runtime_entity("run", command_run_id, now)

    def command_run_vars(self, command_run_id: str) -> dict[str, str]:
        """Return the persisted variable snapshot for one command run."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT name, value
                FROM command_run_vars
                WHERE command_run_id = ?
                ORDER BY name
                """,
                (command_run_id,),
            )
            return {row["name"]: row["value"] for row in rows}

    def command_run_var_rows(self, command_run_id: str) -> list[sqlite3.Row]:
        """Return variable snapshot rows for display/audit output."""
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT *
                    FROM command_run_vars
                    WHERE command_run_id = ?
                    ORDER BY name
                    """,
                    (command_run_id,),
                )
            )

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

    def recent_events(self, limit: int = 25) -> list[Event]:
        """Return the latest events as a chronological slice."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM (
                    SELECT * FROM events ORDER BY id DESC LIMIT ?
                )
                ORDER BY id ASC
                """,
                (limit,),
            )
            return [Event.from_row(row) for row in rows]

    def latest_event_id(self) -> int:
        """Return the current highest event id, or zero for an empty DB."""
        with self.connect() as conn:
            return int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        after_id: int = 0,
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
                WHERE id > ?
                  AND (? IS NULL OR topic = ?)
                  AND (? IS NULL OR command_run_id = ?)
                  AND (? IS NULL OR pipeline_id = ?)
                ORDER BY id ASC
                LIMIT ?
                """,
                (after_id, topic, topic, command_run_id, command_run_id, pipeline_id, pipeline_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_for_job(self, job_id: int, *, limit: int = 1000) -> list[Event]:
        """Return events associated with a job id through scope or payload."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT events.*
                FROM events
                LEFT JOIN command_run_vars
                  ON command_run_vars.command_run_id = events.command_run_id
                  OR command_run_vars.pipeline_id = events.pipeline_id
                WHERE command_run_vars.job_id = ?
                   OR json_extract(events.payload_json, '$.job_id') = ?
                ORDER BY events.id ASC
                LIMIT ?
                """,
                (job_id, job_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_for_serial(self, serial: str, *, limit: int = 1000) -> list[Event]:
        """Return events associated with a globally unique audit serial."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                WHERE command_run_id = ?
                   OR pipeline_id = ?
                   OR json_extract(payload_json, '$.serial') = ?
                   OR json_extract(payload_json, '$.job_serial') = ?
                   OR json_extract(payload_json, '$.artifact_id') = ?
                   OR json_extract(payload_json, '$.target_id') = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (serial, serial, serial, serial, serial, serial, limit),
            )
            return [Event.from_row(row) for row in rows]

    def serials(self) -> list[str]:
        """Return known durable runtime/resource/artifact serial values."""
        values: set[str] = set()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT command_run_id AS serial FROM events WHERE command_run_id IS NOT NULL
                UNION
                SELECT pipeline_id AS serial FROM events WHERE pipeline_id IS NOT NULL
                UNION
                SELECT command_run_id AS serial FROM command_run_vars WHERE command_run_id IS NOT NULL
                UNION
                SELECT pipeline_id AS serial FROM command_run_vars WHERE pipeline_id IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.serial') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.serial') IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.job_serial') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.job_serial') IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.artifact_id') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.artifact_id') IS NOT NULL
                UNION
                SELECT serial FROM jobs WHERE serial IS NOT NULL
                """
            ).fetchall()
        for row in rows:
            if row["serial"] is not None:
                values.add(str(row["serial"]))
        return sorted(values)

    def artifact_counts_by_run(self) -> dict[str, int]:
        """Return artifact counts keyed by durable command-run serial."""
        return self.artifact_counts("command_run_id")

    def artifact_counts_by_pipeline(self) -> dict[str, int]:
        """Return artifact counts keyed by durable pipeline serial."""
        return self.artifact_counts("pipeline_id")

    def artifact_counts_by_job(self) -> dict[str, int]:
        """Return artifact counts keyed by local job id string."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT json_extract(payload_json, '$.job_id') AS target_id,
                       COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
                FROM events
                WHERE topic = 'artifact.attached'
                  AND json_extract(payload_json, '$.job_id') IS NOT NULL
                GROUP BY target_id
                """
            ).fetchall()
        return {str(row["target_id"]): int(row["artifacts"]) for row in rows}

    def artifact_counts(self, scope_column: str) -> dict[str, int]:
        """Return artifact counts grouped by a trusted events scope column."""
        match scope_column:
            case "command_run_id":
                sql = """
                    SELECT command_run_id AS target_id,
                           COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
                    FROM events
                    WHERE topic = 'artifact.attached'
                      AND command_run_id IS NOT NULL
                    GROUP BY command_run_id
                """
            case "pipeline_id":
                sql = """
                    SELECT pipeline_id AS target_id,
                           COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
                    FROM events
                    WHERE topic = 'artifact.attached'
                      AND pipeline_id IS NOT NULL
                    GROUP BY pipeline_id
                """
            case _:
                raise ValueError(f"unsupported artifact count scope: {scope_column}")
        with self.connect() as conn:
            rows = conn.execute(sql).fetchall()
        return {str(row["target_id"]): int(row["artifacts"]) for row in rows}

    def runtime_names(self) -> dict[tuple[str, str], str]:
        """Return latest user-assigned names keyed by target type and id."""
        names: dict[tuple[str, str], str] = {}
        for event in self.events_matching(topic="runtime.name.assigned", limit=100000):
            target_type = event.payload.get("target_type")
            target_id = event.payload.get("target_id")
            name = event.payload.get("name")
            if target_type is not None and target_id is not None and name is not None:
                names[(str(target_type), str(target_id))] = str(name)
        return names

    def runs(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize commandlet executions that produced events."""
        self.ensure_run_aliases()
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT
                        events.command_run_id,
                        events.pipeline_id,
                        events.source,
                        COUNT(DISTINCT events.id) AS events,
                        MIN(events.created_at) AS first_event,
                        MAX(events.created_at) AS last_event,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        SUM(CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN 1 ELSE 0 END) AS active_jobs
                    FROM events
                    LEFT JOIN command_run_vars
                      ON command_run_vars.command_run_id = events.command_run_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    WHERE events.command_run_id IS NOT NULL
                    GROUP BY events.command_run_id, events.pipeline_id, events.source
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY MAX(events.id) DESC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def pipelines(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize known pipeline IDs from events and run-variable snapshots."""
        self.ensure_pipeline_aliases()
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    WITH known_pipelines AS (
                        SELECT pipeline_id FROM events WHERE pipeline_id IS NOT NULL
                        UNION
                        SELECT pipeline_id FROM command_run_vars WHERE pipeline_id IS NOT NULL
                    )
                    SELECT
                        known_pipelines.pipeline_id,
                        MIN(command_run_vars.job_id) AS job_id,
                        COUNT(DISTINCT command_run_vars.command_run_id) AS runs,
                        COUNT(DISTINCT events.id) AS events,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        SUM(CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN 1 ELSE 0 END) AS active_jobs,
                        MIN(COALESCE(command_run_vars.created_at, events.created_at)) AS first_seen,
                        MAX(COALESCE(command_run_vars.created_at, events.created_at)) AS last_seen
                    FROM known_pipelines
                    LEFT JOIN command_run_vars
                      ON command_run_vars.pipeline_id = known_pipelines.pipeline_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    LEFT JOIN events
                      ON events.pipeline_id = known_pipelines.pipeline_id
                    GROUP BY known_pipelines.pipeline_id
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY last_seen DESC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def run_aliases(self) -> dict[str, str]:
        """Return stable local run IDs keyed by durable run serial."""
        self.ensure_run_aliases()
        return self.runtime_aliases("run")

    def pipeline_aliases(self) -> dict[str, str]:
        """Return stable local pipeline IDs keyed by durable pipeline serial."""
        self.ensure_pipeline_aliases()
        return self.runtime_aliases("pipeline")

    def resolve_run_serial(self, value: str) -> str:
        """Resolve a local run id or durable serial to the durable run serial."""
        return self.resolve_runtime_serial("run", value)

    def resolve_pipeline_serial(self, value: str) -> str:
        """Resolve a local pipeline id or durable serial to the durable pipeline serial."""
        return self.resolve_runtime_serial("pipeline", value)

    def runtime_aliases(self, entity_type: str) -> dict[str, str]:
        """Return local IDs keyed by serial for one runtime entity type."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT serial, local_id
                FROM runtime_entities
                WHERE entity_type = ?
                ORDER BY local_id
                """,
                (entity_type,),
            ).fetchall()
        return {str(row["serial"]): str(row["local_id"]) for row in rows}

    def resolve_runtime_serial(self, entity_type: str, value: str) -> str:
        """Resolve a local runtime id or pass through an explicit serial."""
        if value.isdigit():
            with self.connect() as conn:
                row = conn.execute(
                    """
                    SELECT serial
                    FROM runtime_entities
                    WHERE entity_type = ? AND local_id = ?
                    """,
                    (entity_type, int(value)),
                ).fetchone()
            if row is not None:
                return str(row["serial"])
        return value

    def ensure_run_aliases(self) -> None:
        """Allocate stable local IDs for known command runs."""
        rows = sorted(
            self.runs_without_alias_backfill(active_only=False),
            key=lambda row: (row["first_event"] or "", row["command_run_id"] or ""),
        )
        for row in rows:
            serial = row["command_run_id"]
            if serial is not None:
                self.ensure_runtime_entity("run", str(serial), row["first_event"])

    def ensure_pipeline_aliases(self) -> None:
        """Allocate stable local IDs for known pipelines."""
        rows = sorted(
            self.pipelines_without_alias_backfill(active_only=False),
            key=lambda row: (row["first_seen"] or "", row["pipeline_id"] or ""),
        )
        for row in rows:
            serial = row["pipeline_id"]
            if serial is not None:
                self.ensure_runtime_entity("pipeline", str(serial), row["first_seen"])

    def ensure_runtime_entity(self, entity_type: str, serial: str, created_at: str | None = None) -> int:
        """Allocate a stable local ID for a durable runtime serial."""
        created = created_at or datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT local_id FROM runtime_entities WHERE entity_type = ? AND serial = ?",
                (entity_type, serial),
            ).fetchone()
            if row is not None:
                return int(row["local_id"])
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT local_id FROM runtime_entities WHERE entity_type = ? AND serial = ?",
                    (entity_type, serial),
                ).fetchone()
                if row is not None:
                    conn.execute("COMMIT")
                    return int(row["local_id"])
                next_id = int(
                    conn.execute(
                        "SELECT COALESCE(MAX(local_id), 0) + 1 FROM runtime_entities WHERE entity_type = ?",
                        (entity_type,),
                    ).fetchone()[0]
                )
                conn.execute(
                    """
                    INSERT INTO runtime_entities(entity_type, local_id, serial, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (entity_type, next_id, serial, created),
                )
                conn.execute("COMMIT")
                return next_id
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def runs_without_alias_backfill(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize runs without recursively allocating local IDs."""
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT
                        events.command_run_id,
                        events.pipeline_id,
                        events.source,
                        COUNT(DISTINCT events.id) AS events,
                        MIN(events.created_at) AS first_event,
                        MAX(events.created_at) AS last_event,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        SUM(CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN 1 ELSE 0 END) AS active_jobs
                    FROM events
                    LEFT JOIN command_run_vars
                      ON command_run_vars.command_run_id = events.command_run_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    WHERE events.command_run_id IS NOT NULL
                    GROUP BY events.command_run_id, events.pipeline_id, events.source
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY MAX(events.id) DESC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def pipelines_without_alias_backfill(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize pipelines without recursively allocating local IDs."""
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    WITH known_pipelines AS (
                        SELECT pipeline_id FROM events WHERE pipeline_id IS NOT NULL
                        UNION
                        SELECT pipeline_id FROM command_run_vars WHERE pipeline_id IS NOT NULL
                    )
                    SELECT
                        known_pipelines.pipeline_id,
                        MIN(command_run_vars.job_id) AS job_id,
                        COUNT(DISTINCT command_run_vars.command_run_id) AS runs,
                        COUNT(DISTINCT events.id) AS events,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        SUM(CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN 1 ELSE 0 END) AS active_jobs,
                        MIN(COALESCE(command_run_vars.created_at, events.created_at)) AS first_seen,
                        MAX(COALESCE(command_run_vars.created_at, events.created_at)) AS last_seen
                    FROM known_pipelines
                    LEFT JOIN command_run_vars
                      ON command_run_vars.pipeline_id = known_pipelines.pipeline_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    LEFT JOIN events
                      ON events.pipeline_id = known_pipelines.pipeline_id
                    GROUP BY known_pipelines.pipeline_id
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY last_seen DESC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )


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


def process_exists(pid: int) -> bool:
    """Return whether an OS process currently exists for a recorded PID."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def new_serial(prefix: str) -> str:
    """Return a durable serial for auditable entities."""
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    return f"{safe_prefix}-{uuid.uuid4().hex}"


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
