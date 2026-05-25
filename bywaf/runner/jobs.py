"""Background job lifecycle helpers for the runner subsystem.

Provides job lifecycle event publication plus child-process entry points for
background command lines and attached pipeline stages.

Used by:
- runner.core: starts background processes and records job request events.
- tests: import background entry points to validate job execution behavior.
"""

from __future__ import annotations

import multiprocessing as mp
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..command_parser import parse_pipeline
from ..db import EventStore
from ..events import Event
from ..registry import PluginRegistry

if TYPE_CHECKING:
    from .context import StageRun



@dataclass(slots=True)
class JobLifecycle:
    """Small helper for publishing consistent job lifecycle events."""

    db: EventStore
    job_id: int
    command_line: str
    request_event: Event | None = None
    job_serial: str | None = None

    @classmethod
    def create(cls, db: EventStore, command_line: str, pid: int | None, status: str = "queued") -> "JobLifecycle":
        """Record a new job and its requested event."""
        job_id = db.record_job(command_line.strip(), pid, status)
        lifecycle = cls(db, job_id, command_line.strip())
        lifecycle.job_serial = db.job_serial(job_id)
        lifecycle.request_event = lifecycle.requested()
        return lifecycle

    def requested(self) -> Event:
        """Publish that the framework accepted a job request."""
        return self.db.publish("job.requested", self.payload({"command": self.command_line}), "runner")

    def claim(self, pid: int | None) -> bool:
        """Try to claim the job for one process and audit the result."""
        if not self.db.claim_job(self.job_id, pid):
            self.db.publish("job.claim.denied", self.payload({"pid": pid}), "runner")
            return False
        self.db.publish("job.claimed", self.payload({"pid": pid}), "runner")
        return True

    def start(self, pid: int | None) -> None:
        """Mark the job running and publish the start event."""
        self.db.update_job_status(self.job_id, "running")
        self.db.publish("job.started", self.payload({"pid": pid, "command": self.command_line}), "runner")

    def fail(self, error: str) -> None:
        """Mark the job failed and publish the failure event."""
        self.db.publish("job.failed", self.payload({"command": self.command_line, "error": error}), "runner")
        self.db.finish_job(self.job_id, "failed")

    def finish(self) -> None:
        """Mark the job finished and publish the completion event."""
        self.db.publish("job.finished", self.payload({"command": self.command_line}), "runner")
        self.db.finish_job(self.job_id, "finished")

    def payload(self, values: dict[str, object]) -> dict[str, object]:
        """Return job lifecycle payload values with local and serial IDs."""
        if self.job_serial is None:
            self.job_serial = self.db.job_serial(self.job_id)
        payload: dict[str, object] = {
            "job_id": self.job_id,
            "job_serial": self.job_serial,
            "serial": self.job_serial,
            **values,
        }
        row = self.db.job(self.job_id)
        if row is not None and row["started_at"]:
            payload["started_at"] = row["started_at"]
        return payload


def run_background_job(
    db_path: str,
    db_passphrase: str | None,
    job_id: int,
    command_line: str,
    pipeline_id: str,
    stages: tuple[StageRun, ...],
) -> None:
    """Child-process entry point for a background pipeline.

    The child reopens the database and rediscovers bundled plugins instead of
    inheriting live connection/plugin objects from the parent process.
    """
    try:
        db = EventStore(Path(db_path), passphrase=db_passphrase)
        pid = mp.current_process().pid
        lifecycle = JobLifecycle(db, job_id, command_line)
        if not lifecycle.claim(pid):
            return
    except Exception:
        # The parent may have exited or removed a temporary database before the
        # child starts. There is nowhere reliable to record that failure, so the
        # child exits quietly instead of printing a multiprocessing traceback.
        return
    try:
        lifecycle.start(pid)
        from .core import Runner

        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        pipeline = parse_pipeline(
            command_line,
            command_resolver=runner.registry.resolve_commandlet_name,
            command_scope_resolver=runner.registry.variable_scope,
        )
        if pipeline.background:
            runner.run_pipeline_processes(pipeline.commands, pipeline_id=pipeline_id, stages=stages)
        else:
            runner.run_pipeline(pipeline.commands, pipeline_id=pipeline_id, stages=stages)
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()


def run_attached_pipeline_job(
    db_path: str,
    db_passphrase: str | None,
    job_id: int,
    command_line: str,
    pipeline_id: str,
    stage: StageRun,
) -> None:
    """Child-process entry point for a commandlet attached to a live pipeline."""
    try:
        db = EventStore(Path(db_path), passphrase=db_passphrase)
        pid = mp.current_process().pid
        lifecycle = JobLifecycle(db, job_id, command_line)
        if not lifecycle.claim(pid):
            return
    except Exception:
        return
    try:
        lifecycle.start(pid)
        from .core import Runner

        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        runner.run_pipeline((stage.invocation,), pipeline_id=pipeline_id, stages=(stage,))
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()
