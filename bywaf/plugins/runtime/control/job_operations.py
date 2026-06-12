"""Runtime control operations for one job.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

import os
import signal

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import cancel_job, kill_job

from .queued_actions import print_queued_actions
from .signals import publish_runtime_signal


def pause_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Record or apply a pause request for one job.

    Called by: `runtime.control.actions` and target-level pause operations.
    """
    events = context.event_store("job pause")
    runtime = context.runtime_store("job pause")
    context.audit_capability("framework.job.control")
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "pause", {}, mode="hard" if hard else "soft")
    events.publish(
        "job.pause.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGSTOP)
    runtime.update_job_status(int(row["id"]), "paused" if hard else "pausing")
    context.output(f"{'hard' if hard else 'soft'} pause requested for job {row['id']}")


def resume_job(context: CommandContext, row, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Record or apply a resume request for one job.

    Called by: `runtime.control.actions` and target-level resume operations.
    """
    events = context.event_store("job resume")
    runtime = context.runtime_store("job resume")
    context.audit_capability("framework.job.control")
    if listonly:
        print_queued_actions(context, "job", str(row["id"]))
        return
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "resume", {}, mode="hard" if hard else "soft")
    events.publish(
        "job.resume.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGCONT)
    runtime.update_job_status(int(row["id"]), "running")
    context.output(f"resume requested for job {row['id']}")


def stop_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Soft-cancel or hard-kill one job.

    Called by: `runtime.control.actions` and target-level stop operations.
    """
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "stop", {}, mode="hard" if hard else "soft")
    context.event_store("job stop").publish(
        "job.stop.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        kill_job(context, row)
    else:
        cancel_job(context, row)


def signal_job_process(row, sig: signal.Signals) -> None:
    """Send a hard-control signal to a recorded job process.

    Called by: hard `pause_job()` and `resume_job()` operations.
    """
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        raise ValueError(f"job {row['id']} process is not running") from None
