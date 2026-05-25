"""Store protocol definitions for persistence abstractions.

Provides typing protocols that describe event, runtime, artifact, and secret
store behavior without binding callers to the SQLite implementation.

Used by:
- tests and future backends: validate storage contracts.
- runner-adjacent code: express expected store capabilities."""


from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .artifacts import Artifact, ArtifactVerification
from .events import Event
from .subscriptions import Subscription


@runtime_checkable
class EventStoreProtocol(Protocol):
    """Append-only event bus and audit-log storage."""

    path: Path
    passphrase: str | None

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
        """Persist one event and return it with its durable id."""
        ...

    def fetch(self, subscription: Subscription) -> list[Event]:
        """Return events matching a scoped subscription."""
        ...

    def poll(
        self,
        subscription: Subscription,
        *,
        timeout_seconds: float = 0,
        interval_seconds: float = 0.25,
    ) -> list[Event]:
        """Poll the event store until matching events arrive or timeout."""
        ...

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events filtered by topic and runtime scope."""
        ...

    def events_for_topic(self, topic: str, limit: int = 100) -> list[Event]:
        """Return events for one topic."""
        ...

    def event_by_id(self, event_id: int) -> Event | None:
        """Return one event by durable id."""
        ...

    def recent_events(self, limit: int = 25) -> list[Event]:
        """Return the latest events in chronological order."""
        ...

    def latest_event_id(self) -> int:
        """Return the highest event id currently stored."""
        ...

    def topics(self) -> list[str]:
        """Return known event topics."""
        ...

    def events_for_job(self, job_id: int, *, limit: int = 1000) -> list[Event]:
        """Return events associated with one local job id."""
        ...

    def events_for_serial(self, serial: str, *, limit: int = 1000) -> list[Event]:
        """Return events associated with one durable serial."""
        ...

    def serials(self) -> list[str]:
        """Return durable serial values known to the event store."""
        ...


@runtime_checkable
class RuntimeStoreProtocol(Protocol):
    """Runtime metadata storage for jobs, pipelines, runs, and control state."""

    def record_job(self, command_line: str, pid: int | None, status: str) -> int:
        """Create a job row and return its local id."""
        ...

    def update_job_pid(self, job_id: int, pid: int | None) -> None:
        """Attach or replace the process id for a job."""
        ...

    def claim_job(self, job_id: int, pid: int | None) -> bool:
        """Atomically claim a queued job for a worker process."""
        ...

    def update_job_status(self, job_id: int, status: str) -> None:
        """Update a job status without marking the job finished."""
        ...

    def finish_job(self, job_id: int, status: str) -> None:
        """Mark a job terminal."""
        ...

    def jobs(self, *, active_only: bool = False) -> list[Any]:
        """Return known jobs."""
        ...

    def job(self, job_id: int) -> Any | None:
        """Return one job row."""
        ...

    def job_serial(self, job_id: int | str) -> str | None:
        """Return a durable serial for one local job id."""
        ...

    def job_id_for_serial(self, serial: str) -> str | None:
        """Return the local job id for a durable job serial."""
        ...

    def jobs_for_pipeline(self, pipeline_id: str) -> list[Any]:
        """Return jobs associated with a pipeline serial."""
        ...

    def jobs_for_run(self, command_run_id: str) -> list[Any]:
        """Return jobs associated with a pipeline-step serial."""
        ...

    def run_serial_exists(self, serial: str) -> bool:
        """Return whether a durable step serial is known."""
        ...

    def request_cancellation(
        self,
        target_type: str,
        target_id: str,
        reason: str | None = None,
    ) -> None:
        """Persist a cooperative cancellation request."""
        ...

    def cancellation_requested(
        self,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> bool:
        """Return whether a matching cancellation request exists."""
        ...

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
        """Persist the effective variable snapshot for one pipeline step."""
        ...

    def command_run_vars(self, command_run_id: str) -> dict[str, str]:
        """Return the persisted variable snapshot for one pipeline step."""
        ...

    def command_run_var_rows(self, command_run_id: str) -> list[Any]:
        """Return variable snapshot rows for display/audit output."""
        ...

    def runtime_names(self) -> dict[tuple[str, str], str]:
        """Return latest user-assigned names keyed by runtime target."""
        ...

    def runs(self, *, active_only: bool = False) -> list[Any]:
        """Return summarized pipeline steps."""
        ...

    def pipelines(self, *, active_only: bool = False) -> list[Any]:
        """Return summarized pipelines."""
        ...

    def run_aliases(self) -> dict[str, str]:
        """Return local step ids keyed by durable step serial."""
        ...

    def pipeline_aliases(self) -> dict[str, str]:
        """Return local pipeline ids keyed by durable pipeline serial."""
        ...

    def resolve_run_serial(self, value: str) -> str:
        """Resolve a local step id or durable serial to a step serial."""
        ...

    def resolve_pipeline_serial(self, value: str) -> str:
        """Resolve a local pipeline id or durable serial to a pipeline serial."""
        ...

    def ensure_runtime_entity(
        self,
        entity_type: str,
        serial: str,
        created_at: str | None = None,
    ) -> int:
        """Allocate or return a stable local id for a durable runtime serial."""
        ...

    def artifact_counts_by_run(self) -> dict[str, int]:
        """Return artifact counts keyed by pipeline-step serial."""
        ...

    def artifact_counts_by_pipeline(self) -> dict[str, int]:
        """Return artifact counts keyed by pipeline serial."""
        ...

    def artifact_counts_by_job(self) -> dict[str, int]:
        """Return artifact counts keyed by local job id."""
        ...


@runtime_checkable
class ArtifactStoreProtocol(Protocol):
    """Artifact body and provenance storage."""

    path: Path
    passphrase: str | None

    def attach_file(
        self,
        path: Path,
        *,
        name: str | None = None,
        note: str | None = None,
        commandlet: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> Artifact:
        """Store one file as an artifact."""
        ...

    def get(self, artifact: int | str) -> Artifact:
        """Return one artifact by local row id or durable artifact id."""
        ...

    def list(
        self,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Return artifacts matching optional provenance selectors."""
        ...

    def verify(self, artifacts: list[Artifact]) -> list[ArtifactVerification]:
        """Verify artifact bodies against stored size and hash metadata."""
        ...

    def remove(self, artifact: Artifact) -> None:
        """Delete one artifact."""
        ...

    def attach_existing(
        self,
        artifact: Artifact,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
        note: str | None = None,
    ) -> Artifact:
        """Update one artifact's provenance attachment."""
        ...

    def replace_file(
        self,
        artifact: Artifact,
        path: Path,
        *,
        name: str | None = None,
        note: str | None = None,
    ) -> Artifact:
        """Replace one artifact body while preserving its durable id."""
        ...


@runtime_checkable
class MaintenanceStoreProtocol(Protocol):
    """Database maintenance operations used by privileged framework code."""

    path: Path
    passphrase: str | None

    @property
    def encrypted(self) -> bool:
        """Return whether the active store is encrypted."""
        ...

    def checkpoint(self) -> None:
        """Flush pending write-ahead-log state during clean shutdown."""
        ...

    def vacuum(self) -> None:
        """Rebuild storage to reclaim free pages."""
        ...

    def rekey(self, new_passphrase: str) -> None:
        """Change the encryption key for an encrypted store."""
        ...

    def table_counts(self) -> dict[str, int]:
        """Return table-level row counts for status output."""
        ...


@runtime_checkable
class VariableStoreProtocol(Protocol):
    """Session variable storage used by config and completion code."""

    def set(self, key: str, value: Any) -> None:
        """Persist one variable value."""
        ...

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return one variable value."""
        ...

    def update_prefixed(self, prefix: str, values: dict[str, Any]) -> None:
        """Load a set of values under a commandlet/plugin prefix."""
        ...

    def names(self) -> list[str]:
        """Return variable names for completion."""
        ...

    def items(self) -> list[tuple[str, str]]:
        """Return all variable key/value pairs."""
        ...
