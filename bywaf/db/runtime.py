"""Runtime run, pipeline, cancellation, and alias operations for EventStore.

Provides command-run variable snapshots, cancellation checks, run/pipeline
summaries, local runtime aliases, and runtime entity allocation.

Used by:
- db.EventStore: inherits runtime coordination persistence.
- runner, completion, and runtime plugins: inspect and control active work."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from .support import ACTIVE_JOB_STATUSES


class EventStoreRuntimeMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def run_serial_exists(self, serial: str) -> bool:
        """Return whether a durable run serial is known from events or run snapshots."""
        if any(row["command_run_id"] == serial for row in self.runs(active_only=False)):
            return True
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM command_run_vars WHERE command_run_id = ? LIMIT 1",
                (serial,),
            ).fetchone()
        return row is not None

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
