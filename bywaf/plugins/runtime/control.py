"""Convenience runtime-control commandlets for jobs and pipelines."""

from __future__ import annotations

import os
import signal
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.plugins.runtime.job import cancel_job, job_ids, kill_job, require_job
from bywaf.plugins.runtime.pipeline import cancel_pipeline, kill_pipeline, pipeline_ids


class Control(CommandletBase):
    """Shared implementation for runtime control convenience commandlets."""

    action: str

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Dispatch `job=<id>` or `pipeline=<id>` to the specific manager."""
        parser = self.parser()
        parser.add_argument("target")
        parser.add_argument("--force", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parser.add_argument("--listonly", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground(f"{self.action} commands")
        kind, target_id = parse_target(parsed.target)
        hard = parsed.hard or parsed.force
        match (self.action, kind):
            case ("cancel", "job"):
                cancel_job(context, require_job(context, target_id))
            case ("cancel", "pipeline"):
                cancel_pipeline(context, target_id)
            case ("kill", "job"):
                kill_job(context, require_job(context, target_id), force=parsed.force)
            case ("kill", "pipeline"):
                kill_pipeline(context, target_id, force=parsed.force)
            case ("pause", "job"):
                pause_job(context, require_job(context, target_id), hard=hard)
            case ("pause", "pipeline"):
                pause_pipeline(context, target_id, hard=hard)
            case ("resume", "job"):
                resume_job(context, require_job(context, target_id), hard=hard, listonly=parsed.listonly)
            case ("resume", "pipeline"):
                resume_pipeline(context, target_id, hard=hard, listonly=parsed.listonly)
            case ("stop", "job"):
                stop_job(context, require_job(context, target_id), hard=hard)
            case ("stop", "pipeline"):
                stop_pipeline(context, target_id, hard=hard)
            case _:
                raise ValueError(f"unsupported target: {parsed.target}")
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete `job=<id>` and `pipeline=<id>` selectors."""
        selectors = ("job=", "pipeline=")
        if prefix.startswith("job="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"job={job_id}" for job_id in job_ids(context) if job_id.startswith(value_prefix)]
        if prefix.startswith("pipeline="):
            value_prefix = prefix.split("=", 1)[1]
            return [
                f"pipeline={pipeline_id}"
                for pipeline_id in pipeline_ids(context)
                if pipeline_id.startswith(value_prefix)
            ]
        if prefix:
            return [selector for selector in selectors if selector.startswith(prefix)]
        return list(selectors)


@commandlet(
    name="kill",
    description="Hard-terminate a job or pipeline.",
    usage="kill [--force] <job=id|pipeline=id>",
    examples=("kill job=1", "kill --force pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Kill(Control):
    """Hard-terminate a job or pipeline."""

    action = "kill"


@commandlet(
    name="cancel",
    description="Request cooperative cancellation for a job or pipeline.",
    usage="cancel <job=id|pipeline=id>",
    examples=("cancel job=1", "cancel pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Cancel(Control):
    """Request cooperative cancellation for a job or pipeline."""

    action = "cancel"


@commandlet(
    name="pause",
    description="Pause a job or pipeline.",
    usage="pause [--soft|--hard] <job=id|pipeline=id>",
    examples=("pause job=1", "pause --hard pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Pause(Control):
    """Pause a job or pipeline, softly by default."""

    action = "pause"


@commandlet(
    name="resume",
    description="Resume a paused job or pipeline.",
    usage="resume [--listonly] [--soft|--hard] <job=id|pipeline=id>",
    examples=("resume job=1", "resume --listonly pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Resume(Control):
    """Resume a job or pipeline."""

    action = "resume"


@commandlet(
    name="stop",
    description="Stop a job or pipeline.",
    usage="stop [--soft|--hard] <job=id|pipeline=id>",
    examples=("stop job=1", "stop --hard pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Stop(Control):
    """Stop a job or pipeline, softly by default."""

    action = "stop"


def parse_target(target: str) -> tuple[str, str]:
    """Parse a `kind=id` target selector."""
    if "=" not in target:
        raise ValueError("target must be job=<id> or pipeline=<id>")
    kind, target_id = target.split("=", 1)
    if kind not in {"job", "pipeline"} or not target_id:
        raise ValueError("target must be job=<id> or pipeline=<id>")
    return kind, target_id


def pause_job(context: CommandContext, row, *, hard: bool) -> None:
    """Record or apply a pause request for one job."""
    db = context.require_db()
    context.audit_capability("framework.job.control")
    db.publish(
        "job.pause.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGSTOP)
    db.update_job_status(int(row["id"]), "paused" if hard else "pausing")
    context.output(f"{'hard' if hard else 'soft'} pause requested for job {row['id']}")


def resume_job(context: CommandContext, row, *, hard: bool, listonly: bool) -> None:
    """Record or apply a resume request for one job."""
    db = context.require_db()
    context.audit_capability("framework.job.control")
    if listonly:
        context.output(f"queued resume actions for job {row['id']}: resume mode={'hard' if hard else 'soft'}")
        return
    db.publish(
        "job.resume.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGCONT)
    db.update_job_status(int(row["id"]), "running")
    context.output(f"resume requested for job {row['id']}")


def stop_job(context: CommandContext, row, *, hard: bool) -> None:
    """Soft-cancel or hard-kill one job."""
    if hard:
        kill_job(context, row, force=True)
    else:
        cancel_job(context, row)


def pause_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool) -> None:
    """Pause all jobs associated with a pipeline."""
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        pause_job(context, job, hard=hard)


def resume_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, listonly: bool) -> None:
    """Resume all jobs associated with a pipeline."""
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        resume_job(context, job, hard=hard, listonly=listonly)


def stop_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool) -> None:
    """Stop all jobs associated with a pipeline."""
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        stop_job(context, job, hard=hard)


def require_pipeline_id(context: CommandContext, pipeline_id: str) -> str:
    """Validate that a pipeline exists and return its ID."""
    if pipeline_id not in set(pipeline_ids(CompletionContext(db=context.db))):
        raise ValueError(f"unknown pipeline: {pipeline_id}")
    return pipeline_id


def signal_job_process(row, sig: signal.Signals) -> None:
    """Send a hard-control signal to a recorded job process."""
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        raise ValueError(f"job {row['id']} process is not running") from None


def plugin() -> Commandlet:
    """Return the first commandlet when loaded as a single plugin entry."""
    return Kill()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlets provided by this module."""
    return (Kill(), Cancel(), Pause(), Resume(), Stop())
