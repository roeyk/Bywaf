"""Background job lifecycle helpers for the runner subsystem.

Provides job lifecycle event publication and background stage splitting policy.

Used by:
- runner.core: starts background processes and records job request events.
- tests: validate job lifecycle and background stage execution policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..db import EventStore
from ..event import Event


@dataclass(slots=True)
class JobLifecycle:
    """Small helper for publishing consistent job lifecycle events.

    This represents the mutable lifecycle publisher for one background job.
    `JobLifecycle.create()` constructs this when a background job is requested.
    Runner background helpers consume its methods to keep DB status updates and
    `job.*` event payloads in one consistent place.
    """

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
        # Include both names for compatibility with older event consumers that
        # read `serial` and newer code that reads `job_serial`.
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


def should_run_stage_processes(commands: tuple[object, ...]) -> bool:
    """Return whether a background pipeline should split stages into processes.

    A single `&` backgrounds the containing command line but should preserve
    ordinary pipe semantics: stage N passes visible events directly to stage
    N+1.  Process-per-stage execution is reserved for the explicit fan-out form
    where every stage has its own background marker, such as
    `hostscanner ... & | portscanner &`.
    """
    return len(commands) > 1 and all(getattr(command, "background", False) for command in commands)
