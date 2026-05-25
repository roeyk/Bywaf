"""Runtime control commandlets.

Provides a bundled plugin implementation and CommandSpec metadata. Implements job/pipeline pause, resume, stop, cancel, signal, and listing behavior.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import os
import signal
from collections.abc import Callable, Iterable
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
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parser.add_argument("--listonly", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground(f"{self.action} commands")
        validate_control_mode(self.action, soft=parsed.soft, hard=parsed.hard)
        # User-facing selectors are local IDs or durable serials. Normalize them
        # before dispatch so handlers only deal with canonical job/pipeline/run
        # coordinates.
        kind, target_id = resolve_control_target(context, *parse_target(parsed.target), allow_pipeline=True)
        hard = parsed.hard
        handler = CONTROL_HANDLERS.get((self.action, kind))
        if handler is None:
            raise ValueError(f"unsupported target: {parsed.target}")
        handler(context, target_id, hard, parsed.listonly)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete target selectors and runtime IDs."""
        selectors = ("job=", "pipeline=", "step=", "serial=")
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
        if prefix.startswith("step="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"step={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
        if prefix.startswith("serial="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"serial={serial}" for serial in runtime_serial_ids(context) if serial.startswith(value_prefix)]
        if prefix:
            return [selector for selector in selectors if selector.startswith(prefix)]
        return list(selectors)


def validate_control_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject mode flags that would make runtime control semantics ambiguous."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("cancel is always cooperative; use stop --hard or end --hard for forced termination")


@commandlet(
    name="signal",
    description="Send a live-control signal to a job, pipeline, or pipeline step.",
    usage="signal <job=id|step=id|serial=id> <action> [--soft|--hard] [key=value ...]",
    examples=(
        "signal step=1 prune host=192.168.1.50",
        "signal step=1 verbosity level=debug",
        "signal job=1 mute",
        "signal step=1 pause --hard",
    ),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, step=<id>, or serial=<id>", completion=CompletionSpec("choice", ("job=", "step=", "serial=")))
@argument("action", "signal action such as prune, mute, verbosity, pause, resume, stop, end, or kill")
class RuntimeSignal(CommandletBase):
    """Publish audited live-control signals for in-flight commandlets."""

    actions = ("prune", "mute", "unmute", "verbosity", "increase-verbosity", "decrease-verbosity", "pause", "resume", "stop", "end", "kill")

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
        signal_kind, signal_target_id = resolve_control_target(
            context,
            str(parsed["kind"]),
            str(parsed["target_id"]),
            allow_pipeline=False,
        )
        signal_args = cast(dict[str, str], parsed["args"])
        signal_action = str(parsed["action"])
        signal_mode = str(parsed["mode"])
        parsed["kind"] = signal_kind
        parsed["target_id"] = signal_target_id
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
            f"signal requested for {display_target_kind(signal_kind)}={signal_target_id} "
            f"action={signal_action} mode={signal_mode}"
        )
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete target selectors first, then action names."""
        selectors = ("job=", "step=", "serial=")
        if not args:
            return [selector for selector in selectors if selector.startswith(prefix)] if prefix else list(selectors)
        if len(args) == 1 and "=" not in args[0]:
            return [selector for selector in selectors if selector.startswith(prefix)]
        if prefix.startswith("job="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"job={job_id}" for job_id in job_ids(context) if job_id.startswith(value_prefix)]
        if prefix.startswith("step="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"step={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
        if prefix.startswith("serial="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"serial={serial}" for serial in runtime_serial_ids(context) if serial.startswith(value_prefix)]
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
    name="end",
    description="Stop a job, pipeline, or pipeline step; defaults to cooperative cancellation.",
    usage="end [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("end job=1", "end --hard pipeline=1", "end step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, step=<id>, or serial=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=", "serial=")))
class End(Control):
    """Stop a job or pipeline, softly by default."""

    action = "end"


@commandlet(
    name="kill",
    description="Synonym for end; defaults to cooperative cancellation.",
    usage="kill [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("kill job=1", "kill --hard pipeline=1", "kill step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, step=<id>, or serial=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=", "serial=")))
class Kill(Control):
    """Synonym for `end`, softly by default."""

    action = "end"


@commandlet(
    name="cancel",
    description="Request cooperative cancellation for a job or pipeline.",
    usage="cancel <job=id|pipeline=id|step=id>",
    examples=("cancel job=1", "cancel pipeline=1", "cancel step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or step=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=")))
class Cancel(Control):
    """Request cooperative cancellation for a job or pipeline."""

    action = "cancel"


@commandlet(
    name="pause",
    description="Pause a job or pipeline.",
    usage="pause [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("pause job=1", "pause --hard pipeline=1", "pause step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or step=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=")))
class Pause(Control):
    """Pause a job or pipeline, softly by default."""

    action = "pause"


@commandlet(
    name="resume",
    description="Resume a paused job or pipeline.",
    usage="resume [--listonly] [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("resume job=1", "resume --listonly pipeline=1", "resume step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or step=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=")))
class Resume(Control):
    """Resume a job or pipeline."""

    action = "resume"


@commandlet(
    name="stop",
    description="Stop a job or pipeline.",
    usage="stop [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("stop job=1", "stop --hard pipeline=1", "stop step=1"),
    capabilities=("framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id>, pipeline=<id>, or step=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=")))
class Stop(Control):
    """Stop a job or pipeline, softly by default."""

    action = "stop"


def parse_target(target: str) -> tuple[str, str]:
    """Parse a `kind=id` target selector."""
    if "=" not in target:
        raise ValueError("target must be job=<id>, pipeline=<id>, step=<id>, or serial=<id>")
    kind, target_id = target.split("=", 1)
    if kind not in {"job", "pipeline", "step", "serial"} or not target_id:
        raise ValueError("target must be job=<id>, pipeline=<id>, step=<id>, or serial=<id>")
    return kind, target_id


def resolve_control_target(
    context: CommandContext,
    kind: str,
    target_id: str,
    *,
    allow_pipeline: bool,
) -> tuple[str, str]:
    """Resolve local IDs and durable serials to canonical runtime control targets."""
    runtime = context.runtime_store("control")
    if kind == "serial":
        # serial= is durable and can identify several runtime entity kinds. The
        # caller decides whether pipeline serials are meaningful for its command.
        resolved = resolve_runtime_serial_target(context, target_id)
        if resolved[0] == "pipeline" and not allow_pipeline:
            raise ValueError("signal serial= must resolve to a job or run, not a pipeline")
        return resolved
    if kind == "step":
        return "run", runtime.resolve_run_serial(target_id)
    if kind == "pipeline":
        if not allow_pipeline:
            raise ValueError("signal does not target pipelines; use job=, step=, or serial= for a job/step")
        return "pipeline", runtime.resolve_pipeline_serial(target_id)
    return kind, target_id


def display_target_kind(kind: str) -> str:
    """Return the user-facing selector kind for an internal runtime target."""
    return "step" if kind == "run" else kind


def resolve_runtime_serial_target(context: CommandContext, serial: str) -> tuple[str, str]:
    """Resolve a durable serial to job, run, or pipeline target coordinates."""
    runtime = context.runtime_store("control")
    job_id = runtime.job_id_for_serial(serial)
    if job_id is not None:
        return "job", job_id
    if runtime.run_serial_exists(serial):
        return "run", serial
    if any(row["pipeline_id"] == serial for row in runtime.pipelines(active_only=False)):
        return "pipeline", serial
    raise ValueError(f"serial does not identify a controllable runtime entity: {serial}")


def job_id_for_serial(context: CommandContext, serial: str) -> str | None:
    """Return local job id for a durable job serial."""
    return context.runtime_store("control").job_id_for_serial(serial)


def run_serial_exists(context: CommandContext, serial: str) -> bool:
    """Return whether a durable step serial is known from events or step snapshots."""
    return context.runtime_store("control").run_serial_exists(serial)


def parse_signal_args(args: list[str]) -> dict[str, object]:
    """Parse `signal target action [--soft|--hard] [key=value ...]`."""
    if len(args) < 2:
        raise ValueError("signal requires target and action")
    kind, target_id = parse_target(args[0])
    action = normalize_signal_action(args[1])
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


def normalize_signal_action(action: str) -> str:
    """Normalize live-control action aliases to their canonical signal names."""
    return "end" if action == "kill" else action


def signal_default_mode(action: str) -> str:
    """Return the default control mode for a signal action."""
    return "soft"


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
    events = context.event_store("signal")
    # Signals are durable coordination records first. Some actions are also
    # applied immediately by the framework, but commandlets can independently
    # observe these events for cooperative live control.
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
    return events.publish(
        "runtime.signal.requested",
        payload,
        "framework",
        pipeline_id=target_id if target_type == "pipeline" else None,
        command_run_id=target_id if target_type == "run" else None,
    )


def dispatch_framework_signal(context: CommandContext, parsed: dict[str, object]) -> None:
    """Apply framework-native signal actions after publishing the signal."""
    action = str(parsed["action"])
    if action not in {"pause", "resume", "stop", "end"}:
        return
    kind = str(parsed["kind"])
    target_id = str(parsed["target_id"])
    hard = parsed["mode"] == "hard"
    handler = FRAMEWORK_SIGNAL_HANDLERS.get((action, kind))
    if handler is None:
        raise ValueError(f"unsupported signal target: {kind}={target_id}")
    # Keep publication and application separate so the audit trail records the
    # requested action even when a framework-level handler fails.
    handler(context, target_id, hard)


ControlHandler = Callable[[CommandContext, str, bool, bool], None]
SignalHandler = Callable[[CommandContext, str, bool], None]


def control_cancel_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one job."""
    del hard, listonly
    publish_runtime_signal(context, "job", target_id, "stop", {}, mode="soft")
    cancel_job(context, require_job(context, target_id))


def control_cancel_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one pipeline."""
    del hard, listonly
    publish_runtime_signal(context, "pipeline", target_id, "stop", {}, mode="soft")
    cancel_pipeline(context, target_id)


def control_cancel_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one pipeline step."""
    del hard, listonly
    publish_runtime_signal(context, "run", target_id, "stop", {}, mode="soft")
    cancel_run(context, target_id)


def control_end_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one job."""
    del listonly
    publish_runtime_signal(context, "job", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_job(context, target_id, hard)


def control_end_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one pipeline."""
    del listonly
    publish_runtime_signal(context, "pipeline", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_pipeline(context, target_id, hard)


def control_end_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one pipeline step."""
    del listonly
    publish_runtime_signal(context, "run", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_run(context, target_id, hard)


def control_pause_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one job."""
    del listonly
    pause_job(context, require_job(context, target_id), hard=hard)


def control_pause_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one pipeline."""
    del listonly
    pause_pipeline(context, target_id, hard=hard)


def control_pause_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one pipeline step."""
    del listonly
    pause_run(context, target_id, hard=hard)


def control_resume_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one job."""
    resume_job(context, require_job(context, target_id), hard=hard, listonly=listonly)


def control_resume_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one pipeline."""
    resume_pipeline(context, target_id, hard=hard, listonly=listonly)


def control_resume_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one pipeline step."""
    resume_run(context, target_id, hard=hard, listonly=listonly)


def control_stop_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one job."""
    del listonly
    stop_job(context, require_job(context, target_id), hard=hard)


def control_stop_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one pipeline."""
    del listonly
    stop_pipeline(context, target_id, hard=hard)


def control_stop_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one pipeline step."""
    del listonly
    stop_run(context, target_id, hard=hard)


def signal_pause_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one job."""
    pause_job(context, require_job(context, target_id), hard=hard, publish_signal=False)


def signal_pause_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one pipeline."""
    pause_pipeline(context, target_id, hard=hard, publish_signal=False)


def signal_pause_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one pipeline step."""
    pause_run(context, target_id, hard=hard, publish_signal=False)


def signal_resume_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one job."""
    resume_job(context, require_job(context, target_id), hard=hard, listonly=False, publish_signal=False)


def signal_resume_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one pipeline."""
    resume_pipeline(context, target_id, hard=hard, listonly=False, publish_signal=False)


def signal_resume_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one pipeline step."""
    resume_run(context, target_id, hard=hard, listonly=False, publish_signal=False)


def signal_stop_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one job."""
    stop_job(context, require_job(context, target_id), hard=hard, publish_signal=False)


def signal_stop_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one pipeline."""
    stop_pipeline(context, target_id, hard=hard, publish_signal=False)


def signal_stop_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one pipeline step."""
    stop_run(context, target_id, hard=hard, publish_signal=False)


def signal_end_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one job."""
    if hard:
        kill_job(context, require_job(context, target_id))
    else:
        cancel_job(context, require_job(context, target_id))


def signal_end_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one pipeline."""
    if hard:
        kill_pipeline(context, target_id)
    else:
        cancel_pipeline(context, target_id)


def signal_end_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one pipeline step."""
    if hard:
        kill_run(context, target_id)
    else:
        cancel_run(context, target_id)


CONTROL_HANDLERS: dict[tuple[str, str], ControlHandler] = {
    ("cancel", "job"): control_cancel_job,
    ("cancel", "pipeline"): control_cancel_pipeline,
    ("cancel", "run"): control_cancel_run,
    ("end", "job"): control_end_job,
    ("end", "pipeline"): control_end_pipeline,
    ("end", "run"): control_end_run,
    ("pause", "job"): control_pause_job,
    ("pause", "pipeline"): control_pause_pipeline,
    ("pause", "run"): control_pause_run,
    ("resume", "job"): control_resume_job,
    ("resume", "pipeline"): control_resume_pipeline,
    ("resume", "run"): control_resume_run,
    ("stop", "job"): control_stop_job,
    ("stop", "pipeline"): control_stop_pipeline,
    ("stop", "run"): control_stop_run,
}


FRAMEWORK_SIGNAL_HANDLERS: dict[tuple[str, str], SignalHandler] = {
    ("end", "job"): signal_end_job,
    ("end", "pipeline"): signal_end_pipeline,
    ("end", "run"): signal_end_run,
    ("pause", "job"): signal_pause_job,
    ("pause", "pipeline"): signal_pause_pipeline,
    ("pause", "run"): signal_pause_run,
    ("resume", "job"): signal_resume_job,
    ("resume", "pipeline"): signal_resume_pipeline,
    ("resume", "run"): signal_resume_run,
    ("stop", "job"): signal_stop_job,
    ("stop", "pipeline"): signal_stop_pipeline,
    ("stop", "run"): signal_stop_run,
}


def pause_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Record or apply a pause request for one job."""
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
    """Record or apply a resume request for one job."""
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
    """Soft-cancel or hard-kill one job."""
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


def pause_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause all jobs associated with a pipeline."""
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "pause", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline pause").jobs_for_pipeline(resolved_pipeline_id):
        pause_job(context, job, hard=hard, publish_signal=False)


def resume_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume all jobs associated with a pipeline."""
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal and not listonly:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "resume", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline resume").jobs_for_pipeline(resolved_pipeline_id):
        resume_job(context, job, hard=hard, listonly=listonly, publish_signal=False)


def stop_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop all jobs associated with a pipeline."""
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "stop", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline stop").jobs_for_pipeline(resolved_pipeline_id):
        stop_job(context, job, hard=hard, publish_signal=False)


def cancel_run(context: CommandContext, command_run_id: str) -> None:
    """Request cooperative cancellation for one pipeline step."""
    jobs = require_run_jobs(context, command_run_id)
    context.runtime_store("run cancel").request_cancellation("run", command_run_id)
    for job in jobs:
        cancel_job(context, job)
    context.output(f"cancel requested for step {command_run_id}")


def kill_run(context: CommandContext, command_run_id: str) -> None:
    """Hard-kill jobs associated with one pipeline step."""
    for job in require_run_jobs(context, command_run_id):
        kill_job(context, job)
    context.output(f"killed step {command_run_id}")


def pause_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause jobs associated with one pipeline step."""
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "pause", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        pause_job(context, job, hard=hard, publish_signal=False)
    context.event_store("run pause").publish(
        "run.pause.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def resume_run(context: CommandContext, command_run_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume or inspect queued actions for one pipeline step."""
    if listonly:
        print_queued_actions(context, "run", command_run_id)
        return
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "resume", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        resume_job(context, job, hard=hard, listonly=False, publish_signal=False)
    context.event_store("run resume").publish(
        "run.resume.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def stop_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop jobs associated with one pipeline step."""
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "stop", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        stop_job(context, job, hard=hard, publish_signal=False)
    context.event_store("run stop").publish(
        "run.stop.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def require_run_jobs(context: CommandContext, command_run_id: str):
    """Return jobs associated with a run or raise a clear error."""
    jobs = context.runtime_store("run jobs").jobs_for_run(command_run_id)
    if not jobs:
        raise ValueError(f"unknown or inactive step: {command_run_id}")
    return jobs


def require_pipeline_id(context: CommandContext, pipeline_id: str) -> str:
    """Validate that a pipeline exists and return its ID."""
    runtime = context.runtime_store("pipeline")
    if pipeline_id not in {str(row["pipeline_id"]) for row in runtime.pipelines(active_only=False)}:
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
    """Print queued control events for a job, pipeline, or step target."""
    display_type = display_target_kind(target_type)
    context.output(f"queued resume actions for {display_type} {target_id}:")
    events = [
        event
        for event in context.event_store("control queued actions").events_matching(limit=100000)
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
        context.output(f"{event.created_at.isoformat()} {event.topic} {display_type}={target_id} mode={mode}{suffix}")


def control_event_matches(event: Event, target_type: str, target_id: str) -> bool:
    """Return whether a control event belongs to a selected runtime target."""
    if target_type == "job":
        return str(event.payload.get("job_id")) == target_id or (
            event.payload.get("target_type") == "job" and str(event.payload.get("target_id")) == target_id
        )
    if target_type == "pipeline":
        return (
            event.pipeline_id == target_id
            or event.payload.get("pipeline_id") == target_id
            or (event.payload.get("target_type") == "pipeline" and event.payload.get("target_id") == target_id)
        )
    if target_type == "run":
        return (
            event.command_run_id == target_id
            or event.payload.get("command_run_id") == target_id
            or (event.payload.get("target_type") == "run" and event.payload.get("target_id") == target_id)
        )
    return False


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    if context.db is None:
        return []
    return [str(row["command_run_id"]) for row in context.db.runs()]


def runtime_serial_ids(context: CompletionContext) -> list[str]:
    """Return durable runtime serials for signal completion."""
    if context.db is None:
        return []
    values = []
    for serial in context.db.serials():
        if serial.startswith(("artifact-", "plugin-", "script-")):
            continue
        values.append(serial)
    return values


def plugin() -> Commandlet:
    """Return the first commandlet when loaded as a single plugin entry."""
    return End()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlets provided by this module."""
    return (RuntimeSignal(), End(), Kill(), Cancel(), Pause(), Resume(), Stop())
