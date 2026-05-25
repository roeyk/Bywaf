"""Background job state operations for EventStore.

Provides job row creation, status changes, stale-job detection, serial lookup,
and job-to-run/pipeline association helpers.

Used by:
- db.EventStore: inherits background job persistence.
- runner and runtime control plugins: track and manage jobs."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from .support import ACTIVE_JOB_STATUSES, new_serial, process_exists


class EventStoreJobMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Implemented by EventStore."""
        raise NotImplementedError

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

    def job_id_for_serial(self, serial: str) -> str | None:
        """Return the local job id for a durable job serial."""
        self.ensure_job_serials()
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM jobs WHERE serial = ?", (serial,)).fetchone()
        return str(row["id"]) if row is not None else None

    def ensure_job_serials(self) -> None:
        """Backfill durable serials for jobs created before job serial support."""
        with self.connect() as conn:
            rows = conn.execute("SELECT id FROM jobs WHERE serial IS NULL ORDER BY id").fetchall()
            for row in rows:
                conn.execute("UPDATE jobs SET serial = ? WHERE id = ?", (new_serial("job"), int(row["id"])))

    def jobs_for_pipeline(self, pipeline_id: str) -> list[sqlite3.Row]:
        """Return jobs associated with a pipeline-step variable snapshot pipeline."""
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
        """Return jobs associated with one pipeline-step variable snapshot."""
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
