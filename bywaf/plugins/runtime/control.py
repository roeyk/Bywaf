"""Convenience runtime-control commandlets for jobs and pipelines."""

from __future__ import annotations

import os
import signal
from collections.abc import Iterable
from typing import cast

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
                publish_runtime_signal(context, "job", target_id, "stop", {}, mode="soft")
                cancel_job(context, require_job(context, target_id))
            case ("cancel", "pipeline"):
                publish_runtime_signal(context, "pipeline", target_id, "stop", {}, mode="soft")
                cancel_pipeline(context, target_id)
            case ("cancel", "run"):
                publish_runtime_signal(context, "run", target_id, "stop", {}, mode="soft")
                cancel_run(context, target_id)
            case ("kill", "job"):
                publish_runtime_signal(context, "job", target_id, "kill", {}, mode="hard")
                kill_job(context, require_job(context, target_id), force=parsed.force)
            case ("kill", "pipeline"):
                publish_runtime_signal(context, "pipeline", target_id, "kill", {}, mode="hard")
                kill_pipeline(context, target_id, force=parsed.force)
            case ("kill", "run"):
                publish_runtime_signal(context, "run", target_id, "kill", {}, mode="hard")
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
    name="signal",
    description="Send a live-control signal to a job, pipeline, or command run.",
    usage="signal <job=id|pipeline=id|run=id> <action> [--soft|--hard] [key=value ...]",
    examples=(
        "signal run=1 prune host=192.168.1.50",
        "signal run=1 verbosity level=debug",
        "signal pipeline=1 mute",
        "signal run=1 pause --hard",
    ),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or run=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "run=")))
@argument("action", "signal action such as prune, mute, verbosity, pause, resume, stop, or kill")
class RuntimeSignal(CommandletBase):
    """Publish audited live-control signals for in-flight commandlets."""

    actions = ("prune", "mute", "unmute", "verbosity", "increase-verbosity", "decrease-verbosity", "pause", "resume", "stop", "kill")

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Publish a signal and apply framework-native actions when needed."""
        del input_events
        parsed = parse_signal_args(args)
        context.require_foreground("signal command")
        signal_args = cast(dict[str, str], parsed["args"])
        signal_action = str(parsed["action"])
        signal_kind = str(parsed["kind"])
        signal_mode = str(parsed["mode"])
        signal_target_id = str(parsed["target_id"])
        publish_runtime_signal(
            context,
            signal_kind,
            signal_target_id,
            signal_action,
            signal_args,
            mode=signal_mode,
        )
        dispatch_framework_signal(context, parsed)
        context.output(
            f"signal requested for {signal_kind}={signal_target_id} "
            f"action={signal_action} mode={signal_mode}"
        )
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete target selectors first, then action names."""
        selectors = ("job=", "pipeline=", "run=")
        if not args:
            return [selector for selector in selectors if selector.startswith(prefix)] if prefix else list(selectors)
        if len(args) == 1 and "=" not in args[0]:
            return [selector for selector in selectors if selector.startswith(prefix)]
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
        if len(args) == 1:
            return [action for action in self.actions if action.startswith(prefix)]
        if len(args) >= 2:
            return [
                candidate
                for candidate in ("target=", "targets=", "host=", "hosts=", "network=", "networks=", "level=", "reason=")
                if candidate.startswith(prefix)
            ]
        return [
            candidate
            for candidate in ("target=", "targets=", "host=", "hosts=", "network=", "networks=", "level=", "reason=")
            if candidate.startswith(prefix)
        ]


@commandlet(
    name="kill",
    description="Hard-terminate a job or pipeline.",
    usage="kill [--force] <job=id|pipeline=id|run=id>",
    examples=("kill job=1", "kill --force pipeline=1", "kill run=1"),
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
    examples=("cancel job=1", "cancel pipeline=1", "cancel run=1"),
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
    examples=("pause job=1", "pause --hard pipeline=1", "pause run=1"),
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
    examples=("resume job=1", "resume --listonly pipeline=1", "resume run=1"),
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
    examples=("stop job=1", "stop --hard pipeline=1", "stop run=1"),
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


def parse_signal_args(args: list[str]) -> dict[str, object]:
    """Parse `signal target action [--soft|--hard] [key=value ...]`."""
    if len(args) < 2:
        raise ValueError("signal requires target and action")
    kind, target_id = parse_target(args[0])
    action = args[1]
    if action.startswith("--"):
        raise ValueError("signal requires an action after the target")
    mode = signal_default_mode(action)
    payload_args: dict[str, str] = {}
    for token in args[2:]:
        match token:
            case "--hard" | "--force":
                mode = "hard"
            case "--soft":
                mode = "soft"
            case _ if "=" in token:
                key, value = token.split("=", 1)
                if not key or not value:
                    raise ValueError(f"invalid signal argument: {token}")
                payload_args[key] = value
            case _:
                raise ValueError(f"invalid signal argument: {token}")
    return {"kind": kind, "target_id": target_id, "action": action, "args": payload_args, "mode": mode}


def signal_default_mode(action: str) -> str:
    """Return the default control mode for a signal action."""
    return "hard" if action == "kill" else "soft"


def publish_runtime_signal(
    context: CommandContext,
    target_type: str,
    target_id: str,
    action: str,
    args: dict[str, str],
    *,
    mode: str,
) -> Event:
    """Publish the canonical audited runtime signal event."""
    db = context.require_db("signal")
    if target_type in {"job", "run"}:
        context.audit_capability("framework.job.control")
    if target_type in {"pipeline", "run"}:
        context.audit_capability("framework.pipeline.control")
    payload = {
        "target_type": target_type,
        "target_id": target_id,
        "action": action,
        "args": args,
        "mode": mode,
    }
    if target_type == "job":
        payload["job_id"] = target_id
    if target_type == "pipeline":
        payload["pipeline_id"] = target_id
    if target_type == "run":
        payload["command_run_id"] = target_id
    return db.publish(
        "runtime.signal.requested",
        payload,
        "framework",
        pipeline_id=target_id if target_type == "pipeline" else None,
        command_run_id=target_id if target_type == "run" else None,
    )


def dispatch_framework_signal(context: CommandContext, parsed: dict[str, object]) -> None:
    """Apply framework-native signal actions after publishing the signal."""
    action = str(parsed["action"])
    if action not in {"pause", "resume", "stop", "kill"}:
        return
    kind = str(parsed["kind"])
    target_id = str(parsed["target_id"])
    hard = parsed["mode"] == "hard"
    match (action, kind):
        case ("pause", "job"):
            pause_job(context, require_job(context, target_id), hard=hard, publish_signal=False)
        case ("pause", "pipeline"):
            pause_pipeline(context, target_id, hard=hard, publish_signal=False)
        case ("pause", "run"):
            pause_run(context, target_id, hard=hard, publish_signal=False)
        case ("resume", "job"):
            resume_job(context, require_job(context, target_id), hard=hard, listonly=False, publish_signal=False)
        case ("resume", "pipeline"):
            resume_pipeline(context, target_id, hard=hard, listonly=False, publish_signal=False)
        case ("resume", "run"):
            resume_run(context, target_id, hard=hard, listonly=False, publish_signal=False)
        case ("stop", "job"):
            stop_job(context, require_job(context, target_id), hard=hard, publish_signal=False)
        case ("stop", "pipeline"):
            stop_pipeline(context, target_id, hard=hard, publish_signal=False)
        case ("stop", "run"):
            stop_run(context, target_id, hard=hard, publish_signal=False)
        case ("kill", "job"):
            kill_job(context, require_job(context, target_id), force=True)
        case ("kill", "pipeline"):
            kill_pipeline(context, target_id, force=True)
        case ("kill", "run"):
            kill_run(context, target_id, force=True)
        case _:
            raise ValueError(f"unsupported signal target: {kind}={target_id}")


def pause_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Record or apply a pause request for one job."""
    db = context.require_db()
    context.audit_capability("framework.job.control")
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "pause", {}, mode="hard" if hard else "soft")
    db.publish(
        "job.pause.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGSTOP)
    db.update_job_status(int(row["id"]), "paused" if hard else "pausing")
    context.output(f"{'hard' if hard else 'soft'} pause requested for job {row['id']}")


def resume_job(context: CommandContext, row, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Record or apply a resume request for one job."""
    db = context.require_db()
    context.audit_capability("framework.job.control")
    if listonly:
        print_queued_actions(context, "job", str(row["id"]))
        return
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "resume", {}, mode="hard" if hard else "soft")
    db.publish(
        "job.resume.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGCONT)
    db.update_job_status(int(row["id"]), "running")
    context.output(f"resume requested for job {row['id']}")


def stop_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Soft-cancel or hard-kill one job."""
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "stop", {}, mode="hard" if hard else "soft")
    context.require_db().publish(
        "job.stop.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        kill_job(context, row, force=True)
    else:
        cancel_job(context, row)


def pause_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause all jobs associated with a pipeline."""
    if publish_signal:
        publish_runtime_signal(context, "pipeline", require_pipeline_id(context, pipeline_id), "pause", {}, mode="hard" if hard else "soft")
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        pause_job(context, job, hard=hard, publish_signal=False)


def resume_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume all jobs associated with a pipeline."""
    if publish_signal and not listonly:
        publish_runtime_signal(context, "pipeline", require_pipeline_id(context, pipeline_id), "resume", {}, mode="hard" if hard else "soft")
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        resume_job(context, job, hard=hard, listonly=listonly, publish_signal=False)


def stop_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop all jobs associated with a pipeline."""
    if publish_signal:
        publish_runtime_signal(context, "pipeline", require_pipeline_id(context, pipeline_id), "stop", {}, mode="hard" if hard else "soft")
    for job in context.require_db().jobs_for_pipeline(require_pipeline_id(context, pipeline_id)):
        stop_job(context, job, hard=hard, publish_signal=False)


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


def pause_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause jobs associated with one command run."""
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "pause", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        pause_job(context, job, hard=hard, publish_signal=False)
    context.require_db().publish(
        "run.pause.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def resume_run(context: CommandContext, command_run_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume or inspect queued actions for one command run."""
    if listonly:
        print_queued_actions(context, "run", command_run_id)
        return
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "resume", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        resume_job(context, job, hard=hard, listonly=False, publish_signal=False)
    context.require_db().publish(
        "run.resume.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def stop_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop jobs associated with one command run."""
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "stop", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        stop_job(context, job, hard=hard, publish_signal=False)
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
        or event.topic == "runtime.signal.requested"
    ]
    matching = [event for event in events if control_event_matches(event, target_type, target_id)]
    if not matching:
        context.output("none")
        return
    for event in matching:
        mode = event.payload.get("mode", "")
        action = event.payload.get("action", "")
        suffix = f" action={action}" if action else ""
        context.output(f"{event.created_at.isoformat()} {event.topic} {target_type}={target_id} mode={mode}{suffix}")


def control_event_matches(event: Event, target_type: str, target_id: str) -> bool:
    """Return whether a control event belongs to a selected runtime target."""
    match target_type:
        case "job":
            return str(event.payload.get("job_id")) == target_id or (
                event.payload.get("target_type") == "job" and str(event.payload.get("target_id")) == target_id
            )
        case "pipeline":
            return (
                event.pipeline_id == target_id
                or event.payload.get("pipeline_id") == target_id
                or (event.payload.get("target_type") == "pipeline" and event.payload.get("target_id") == target_id)
            )
        case "run":
            return (
                event.command_run_id == target_id
                or event.payload.get("command_run_id") == target_id
                or (event.payload.get("target_type") == "run" and event.payload.get("target_id") == target_id)
            )
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
    return (RuntimeSignal(), Kill(), Cancel(), Pause(), Resume(), Stop())
