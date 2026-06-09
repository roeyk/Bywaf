"""Runtime store protocol for job, pipeline, and run metadata.

Used by: runtime commandlets, runner orchestration, and display code that need
job/run/pipeline metadata without depending on the SQLite store class.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


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
