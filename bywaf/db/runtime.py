"""Runtime run, pipeline, cancellation, and alias operations for EventStore.

Provides pipeline-step variable snapshots, cancellation checks, run/pipeline
summaries, local runtime aliases, and runtime entity allocation.

Used by:
- db.EventStore: inherits runtime coordination persistence.
- runner, completion, and runtime plugins: inspect and control active work."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from .runtime_state import EventStoreRuntimeStateMixin
from ..time_format import bywaf_now_iso
from .backends import DatabaseConnection
from .support import ACTIVE_JOB_STATUSES, resolve_serial_match


class EventStoreRuntimeMixin(EventStoreRuntimeStateMixin):
    """Runtime alias and scope-query operations mixed into `EventStore`.

    Consumed by: runner lifecycle code, runtime commandlets, completion helpers,
    and report/inventory scope selectors.
    """

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def run_serial_exists(self, serial: str) -> bool:
        """Return whether a durable step serial is known from events or step snapshots."""
        if any(row["command_run_id"] == serial for row in self.runs(active_only=False)):
            return True
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM command_run_vars WHERE command_run_id = ? LIMIT 1",
                (serial,),
            ).fetchone()
        return row is not None

    def runs(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize commandlet executions that produced events."""
        self.ensure_run_aliases()
        with self.connect() as conn:
            # Runs are reconstructed from events and variable snapshots rather
            # than a separate mutable run table.  Joining to jobs lets the same
            # query power both historical `steps` and active-only views.
            return list(
                conn.execute(
                    """
                    SELECT
                        events.command_run_id,
                        events.pipeline_id,
                        COALESCE(
                            MAX(command_run_vars.commandlet),
                            MIN(CASE WHEN events.source NOT IN ('framework', 'runner') THEN events.source END),
                            MIN(events.source)
                        ) AS source,
                        COUNT(DISTINCT events.id) AS events,
                        MIN(events.created_at) AS first_event,
                        MAX(events.created_at) AS last_event,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        COUNT(DISTINCT CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN jobs.id END) AS active_jobs
                    FROM events
                    LEFT JOIN command_run_vars
                      ON command_run_vars.command_run_id = events.command_run_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    WHERE events.command_run_id IS NOT NULL
                    GROUP BY events.command_run_id, events.pipeline_id
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY MIN(events.id) ASC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def pipelines(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize known pipeline IDs from events and run-variable snapshots."""
        self.ensure_pipeline_aliases()
        with self.connect() as conn:
            # A pipeline can be known because it emitted events or because its
            # background step snapshots were recorded before the child produced
            # output.  Include both so users can inspect newly-started work.
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
                    ORDER BY first_seen ASC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def run_aliases(self) -> dict[str, str]:
        """Return stable local step IDs keyed by durable step serial."""
        self.ensure_run_aliases()
        return self.runtime_aliases("run")

    def pipeline_aliases(self) -> dict[str, str]:
        """Return stable local pipeline IDs keyed by durable pipeline serial."""
        self.ensure_pipeline_aliases()
        return self.runtime_aliases("pipeline")

    def resolve_run_serial(self, value: str) -> str:
        """Resolve a local step id or durable serial to the durable step serial."""
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
        """Resolve a local runtime id, full serial, or unique serial prefix."""
        if value.isdigit():
            # Numeric selectors refer to local per-database ids shown by job,
            # pipeline, and step listings.
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
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT serial
                FROM runtime_entities
                WHERE entity_type = ?
                """,
                (entity_type,),
            ).fetchall()
        serials = [str(row["serial"]) for row in rows]
        # Non-numeric input may be a full durable serial or a unique prefix;
        # leave unknown values unchanged so callers can report scoped errors.
        return resolve_serial_match(value, serials) or value

    def ensure_run_aliases(self) -> None:
        """Allocate stable local IDs for known pipeline steps."""
        # Allocate in chronological order so local ids remain stable and
        # intuitive even though the query helper may otherwise sort newest-first.
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
        # Pipeline aliases follow first-seen order for the same reason step
        # aliases do: users should see small stable ids in work order.
        rows = sorted(
            self.pipelines_missing_alias(active_only=False),
            key=lambda row: (row["first_seen"] or "", row["pipeline_id"] or ""),
        )
        for row in rows:
            serial = row["pipeline_id"]
            if serial is not None:
                self.ensure_runtime_entity("pipeline", str(serial), row["first_seen"])

    def ensure_runtime_entity(self, entity_type: str, serial: str, created_at: str | None = None) -> int:
        """Allocate a stable local ID for a durable runtime serial.

        Durable serials are globally unique but too long for daily REPL use.
        This method assigns per-database local IDs (`1`, `2`, ...) under an
        immediate transaction so concurrent processes do not allocate the same
        local selector.
        """
        created = created_at or bywaf_now_iso()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT local_id FROM runtime_entities WHERE entity_type = ? AND serial = ?",
                (entity_type, serial),
            ).fetchone()
            if row is not None:
                return int(row["local_id"])
            # Lock before computing MAX(local_id)+1.  SQLite does not have a
            # sequence per entity type here, so the read/insert pair must be
            # atomic across foreground and background processes.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT local_id FROM runtime_entities WHERE entity_type = ? AND serial = ?",
                    (entity_type, serial),
                ).fetchone()
                if row is not None:
                    conn.execute("COMMIT")
                    return int(row["local_id"])
                next_row = conn.execute(
                    "SELECT COALESCE(MAX(local_id), 0) + 1 FROM runtime_entities WHERE entity_type = ?",
                    (entity_type,),
                )
                fetched = next_row.fetchone()
                next_id = int(fetched[0]) if fetched is not None else 1
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
        """Summarize runs without recursively allocating local IDs.

        Called by: alias allocation itself; using this avoids recursion through
        `runs()`, which calls `ensure_run_aliases()`.
        """
        with self.connect() as conn:
            return list(
                conn.execute(
                    """
                    SELECT
                        events.command_run_id,
                        events.pipeline_id,
                        COALESCE(
                            MAX(command_run_vars.commandlet),
                            MIN(CASE WHEN events.source NOT IN ('framework', 'runner') THEN events.source END),
                            MIN(events.source)
                        ) AS source,
                        COUNT(DISTINCT events.id) AS events,
                        MIN(events.created_at) AS first_event,
                        MAX(events.created_at) AS last_event,
                        GROUP_CONCAT(DISTINCT jobs.status) AS job_statuses,
                        COUNT(DISTINCT CASE WHEN jobs.status IN (?, ?, ?, ?, ?, ?) THEN jobs.id END) AS active_jobs
                    FROM events
                    LEFT JOIN command_run_vars
                      ON command_run_vars.command_run_id = events.command_run_id
                    LEFT JOIN jobs
                      ON jobs.id = command_run_vars.job_id
                    WHERE events.command_run_id IS NOT NULL
                    GROUP BY events.command_run_id, events.pipeline_id
                    HAVING ? = 0 OR active_jobs > 0
                    ORDER BY MAX(events.id) DESC
                    """,
                    (*ACTIVE_JOB_STATUSES, 1 if active_only else 0),
                )
            )

    def pipelines_missing_alias(self, *, active_only: bool = False) -> list[sqlite3.Row]:
        """Summarize pipelines without recursively allocating local IDs.

        Called by: `ensure_pipeline_aliases()` before local ids exist for all
        known durable pipeline serials.
        """
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
