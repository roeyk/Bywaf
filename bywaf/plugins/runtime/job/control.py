"""Job lookup and control helpers for runtime commandlets.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

import os
import signal

from bywaf.plugin import CommandContext


def require_job(context: CommandContext, job_id: str | None):
    """Return a job row or raise a user-facing error.

    Called by: `job`, `results`, and other runtime commandlets that accept
    local job IDs or durable job serials.
    """
    runtime = context.runtime_store("job")
    if not job_id:
        raise ValueError("job id is required")
    try:
        numeric_id = int(job_id)
    except ValueError:
        resolved = runtime.job_id_for_serial(job_id)
        if resolved is None:
            raise ValueError(f"unknown job: {job_id}") from None
        numeric_id = int(resolved)
    row = runtime.job(numeric_id)
    if row is None and job_id.isdigit():
        resolved = runtime.job_id_for_serial(job_id)
        if resolved is not None:
            row = runtime.job(int(resolved))
    if row is None:
        raise ValueError(f"unknown job: {job_id}")
    return row


def kill_job(context: CommandContext, row) -> None:
    """Forcefully terminate a job process and update its status.

    Called by: `job kill --hard`, pipeline hard-kill operations, and the
    convenience `kill --hard job=...` command.
    """
    runtime = context.runtime_store("job kill")
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        # Hard kill is intentionally separate from cooperative cancellation; it
        # is the operator's escape hatch when a child process ignores requests.
        os.kill(int(pid), signal.SIGKILL)
    except ProcessLookupError:
        runtime.finish_job(int(row["id"]), "missing")
        raise ValueError(f"job {row['id']} process is not running") from None
    runtime.finish_job(int(row["id"]), "killed")
    context.output(f"killed job {row['id']}")


def cancel_job(context: CommandContext, row) -> None:
    """Request cooperative cancellation for one job row.

    Called by: `job cancel`, `job end`, pipeline cancellation, and stop
    convenience commands.
    """
    runtime = context.runtime_store("job cancel")
    context.audit_capability("framework.job.control")
    runtime.request_cancellation("job", str(row["id"]))
    runtime.update_job_status(int(row["id"]), "cancelling")
    context.output(f"cancel requested for job {row['id']}")
