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
        """Dispatch a runtime-control selector to the specific manager."""
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
            case ("cancel", "run"):
                cancel_run(context, target_id)
            case ("kill", "job"):
                kill_job(context, require_job(context, target_id), force=parsed.force)
            case ("kill", "pipeline"):
                kill_pipeline(context, target_id, force=parsed.force)
            case ("kill", "run"):
                kill_run(context, target_id, force=parsed.force)
            case ("pause", "job"):
                pause_job(context, require_job(context, target_id), hard=hard)
            case ("pause", "pipeline"):
                pause_pipeline(context, target_id, hard=hard)
            case ("pause", "run"):
                pause_run(context, target_id, hard=hard)
            case ("resume", "job"):
                resume_job(context, require_job(context, target_id), hard=hard, listonly=parsed.listonly)
            case ("resume", "pipeline"):
                resume_pipeline(context, target_id, hard=hard, listonly=parsed.listonly)
            case ("resume", "run"):
                resume_run(context, target_id, hard=hard, listonly=parsed.listonly)
            case ("stop", "job"):
                stop_job(context, require_job(context, target_id), hard=hard)
            case ("stop", "pipeline"):
                stop_pipeline(context, target_id, hard=hard)
            case ("stop", "run"):
                stop_run(context, target_id, hard=hard)
            case _:
                raise ValueError(f"unsupported target: {parsed.target}")
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete `job=<id>`, `pipeline=<id>`, and `run=<id>` selectors."""
        selectors = ("job=", "pipeline=", "run=")
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
        if prefix.startswith("run="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"run={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
        if prefix:
            return [selector for selector in selectors if selector.startswith(prefix)]
        return list(selectors)


@commandlet(
    name="kill",
    description="Hard-terminate a job or pipeline.",
    usage="kill [--force] <job=id|pipeline=id|run=id>",
    examples=("kill job=1", "kill --force pipeline=pipeline-...", "kill run=hostscanner-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
class Kill(Control):
    """Hard-terminate a job or pipeline."""

    action = "kill"


@commandlet(
    name="cancel",
    description="Request cooperative cancellation for a job or pipeline.",
    usage="cancel <job=id|pipeline=id|run=id>",
    examples=("cancel job=1", "cancel pipeline=pipeline-...", "cancel run=hostscanner-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
class Cancel(Control):
    """Request cooperative cancellation for a job or pipeline."""

    action = "cancel"


@commandlet(
    name="pause",
    description="Pause a job or pipeline.",
    usage="pause [--soft|--hard] <job=id|pipeline=id|run=id>",
    examples=("pause job=1", "pause --hard pipeline=pipeline-...", "pause run=hostscanner-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
class Pause(Control):
    """Pause a job or pipeline, softly by default."""

    action = "pause"


@commandlet(
    name="resume",
    description="Resume a paused job or pipeline.",
    usage="resume [--listonly] [--soft|--hard] <job=id|pipeline=id|run=id>",
    examples=("resume job=1", "resume --listonly pipeline=pipeline-...", "resume run=hostscanner-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
class Resume(Control):
    """Resume a job or pipeline."""

    action = "resume"


@commandlet(
    name="stop",
    description="Stop a job or pipeline.",
    usage="stop [--soft|--hard] <job=id|pipeline=id|run=id>",
    examples=("stop job=1", "stop --hard pipeline=pipeline-...", "stop run=hostscanner-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
class Stop(Control):
    """Stop a job or pipeline, softly by default."""

    action = "stop"


def parse_target(target: str) -> tuple[str, str]:
    """Parse a `kind=id` target selector."""
    if "=" not in target:
        raise ValueError("target must be job=<id>, pipeline=<id>, or run=<id>")
    kind, target_id = target.split("=", 1)
    if kind not in {"job", "pipeline", "run"} or not target_id:
        raise ValueError("target must be job=<id>, pipeline=<id>, or run=<id>")
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
        print_queued_actions(context, "job", str(row["id"]))
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
    context.require_db().publish(
        "job.stop.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
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


def cancel_run(context: CommandContext, command_run_id: str) -> None:
    """Request cooperative cancellation for one command run."""
    jobs = require_run_jobs(context, command_run_id)
    context.require_db().request_cancellation("run", command_run_id)
    for job in jobs:
        cancel_job(context, job)
    context.output(f"cancel requested for run {command_run_id}")


def kill_run(context: CommandContext, command_run_id: str, *, force: bool) -> None:
    """Hard-kill jobs associated with one command run."""
    for job in require_run_jobs(context, command_run_id):
        kill_job(context, job, force=force)
    context.output(f"killed run {command_run_id}" if force else f"terminated run {command_run_id}")


def pause_run(context: CommandContext, command_run_id: str, *, hard: bool) -> None:
    """Pause jobs associated with one command run."""
    for job in require_run_jobs(context, command_run_id):
        pause_job(context, job, hard=hard)
    context.require_db().publish(
        "run.pause.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def resume_run(context: CommandContext, command_run_id: str, *, hard: bool, listonly: bool) -> None:
    """Resume or inspect queued actions for one command run."""
    if listonly:
        print_queued_actions(context, "run", command_run_id)
        return
    for job in require_run_jobs(context, command_run_id):
        resume_job(context, job, hard=hard, listonly=False)
    context.require_db().publish(
        "run.resume.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def stop_run(context: CommandContext, command_run_id: str, *, hard: bool) -> None:
    """Stop jobs associated with one command run."""
    for job in require_run_jobs(context, command_run_id):
        stop_job(context, job, hard=hard)
    context.require_db().publish(
        "run.stop.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def require_run_jobs(context: CommandContext, command_run_id: str):
    """Return jobs associated with a run or raise a clear error."""
    jobs = context.require_db().jobs_for_run(command_run_id)
    if not jobs:
        raise ValueError(f"unknown or inactive run: {command_run_id}")
    return jobs


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


def print_queued_actions(context: CommandContext, target_type: str, target_id: str) -> None:
    """Print queued control events for a job, pipeline, or run target."""
    context.output(f"queued resume actions for {target_type} {target_id}:")
    events = [
        event
        for event in context.require_db().events_matching(limit=100000)
        if event.topic.endswith(".pause.requested")
        or event.topic.endswith(".resume.requested")
        or event.topic.endswith(".stop.requested")
    ]
    matching = [event for event in events if control_event_matches(event, target_type, target_id)]
    if not matching:
        context.output("none")
        return
    for event in matching:
        mode = event.payload.get("mode", "")
        context.output(f"{event.created_at.isoformat()} {event.topic} {target_type}={target_id} mode={mode}")


def control_event_matches(event: Event, target_type: str, target_id: str) -> bool:
    """Return whether a control event belongs to a selected runtime target."""
    match target_type:
        case "job":
            return str(event.payload.get("job_id")) == target_id
        case "pipeline":
            return event.pipeline_id == target_id or event.payload.get("pipeline_id") == target_id
        case "run":
            return event.command_run_id == target_id or event.payload.get("command_run_id") == target_id
        case _:
            return False


def run_ids(context: CompletionContext) -> list[str]:
    """Return command-run IDs for completion."""
    if context.db is None:
        return []
    return [str(row["command_run_id"]) for row in context.db.runs()]


def plugin() -> Commandlet:
    """Return the first commandlet when loaded as a single plugin entry."""
    return Kill()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlets provided by this module."""
    return (Kill(), Cancel(), Pause(), Resume(), Stop())
