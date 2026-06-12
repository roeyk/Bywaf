"""Runtime cancellation and command-run variable snapshot operations.

Used by: `db.runtime.EventStoreRuntimeMixin`, which exposes these methods
through the public `EventStore` facade. These helpers are write-heavy runtime
state operations, separate from run/pipeline summary and alias lookups.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .backends import DatabaseConnection
from ..time_format import bywaf_now_iso

RUN_ASSOCIATION_NAME = "__bywaf.run"


class EventStoreRuntimeStateMixin:
    """Adds cancellation and variable-snapshot methods to `EventStore`.

    Constructed by: multiple inheritance in `db.EventStore`.
    Used by: runner cancellation checks, background jobs, and runtime detail
    views that explain commandlet execution context.
    """

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def ensure_runtime_entity(self, entity_type: str, serial: str, created_at: str | None = None) -> int:
        """Implemented by EventStoreRuntimeMixin."""
        raise NotImplementedError

    def request_cancellation(self, target_type: str, target_id: str, reason: str | None = None) -> None:
        """Record a soft-cancellation request for a job, pipeline, or run."""
        now = bywaf_now_iso()
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
        # Cancellation can be addressed at any runtime scope.  A commandlet step
        # should stop if its job, its pipeline, or the step itself has been
        # requested to stop.
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
        """Persist the effective variables captured for one pipeline step.

        These rows are immutable execution evidence: they explain which
        variables a commandlet saw when it launched and give background
        processes a stable snapshot to reconstruct from.
        """
        now = bywaf_now_iso()
        rows = [
            (job_id, pipeline_id, command_run_id, commandlet, RUN_ASSOCIATION_NAME, "", "association", now),
            *(
                (job_id, pipeline_id, command_run_id, commandlet, name, value, source, now)
                for name, value in sorted(values.items())
            ),
        ]
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
                rows,
            )
        self.ensure_runtime_entity("pipeline", pipeline_id, now)
        self.ensure_runtime_entity("run", command_run_id, now)

    def command_run_vars(self, command_run_id: str) -> dict[str, str]:
        """Return the persisted variable snapshot for one pipeline step."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT name, value
                FROM command_run_vars
                WHERE command_run_id = ?
                  AND name != ?
                ORDER BY name
                """,
                (command_run_id, RUN_ASSOCIATION_NAME),
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
                      AND name != ?
                    ORDER BY name
                    """,
                    (command_run_id, RUN_ASSOCIATION_NAME),
                )
            )
