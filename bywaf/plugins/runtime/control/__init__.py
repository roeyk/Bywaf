"""Runtime control commandlets.

Provides bundled commandlet metadata for job, pipeline, and pipeline-step
pause/resume/stop/end/cancel/signal behavior. Selector resolution and action
application live in focused helper modules.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from typing import cast

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet

from .actions import CONTROL_HANDLERS, dispatch_framework_signal
from .selectors import control_completion, display_target_kind, parse_target, resolve_control_target
from .signal import parse_signal_args
from .signals import publish_runtime_signal


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
        del input_events
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
        handler = CONTROL_HANDLERS.get((self.action, kind))
        if handler is None:
            raise ValueError(f"unsupported target: {parsed.target}")
        handler(context, target_id, parsed.hard, parsed.listonly)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete target selectors and runtime IDs."""
        del args
        return control_completion(context, prefix, allow_pipeline=True) or []


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
)
@argument("target", "job=<id>, step=<id>, or serial=<id>", completion=CompletionSpec("choice", ("job=", "step=", "serial=")))
@argument("action", "signal action such as prune, mute, verbosity, pause, resume, stop, end, or kill")
class RuntimeSignal(CommandletBase):
    """Publish audited live-control signals for in-flight commandlets."""

    actions = ("prune", "mute", "unmute", "verbosity", "increase-verbosity", "decrease-verbosity", "pause", "resume", "stop", "end", "kill")

    def parser(self) -> argparse.ArgumentParser:
        """Return help for live-control signal syntax."""
        parser = argparse.ArgumentParser(
            prog=self.spec.name,
            usage=self.spec.usage,
            description=self.spec.description,
            epilog=(
                "actions: " + ", ".join(self.actions) + "\n\n"
                "examples:\n  " + "\n  ".join(self.spec.examples)
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("target", nargs="?", help="job=<id>, step=<id>, or serial=<id>")
        parser.add_argument("action", nargs="?", help="signal action")
        parser.add_argument("args", nargs="*", help="optional key=value payload arguments")
        parser.add_argument("--hard", action="store_true", help="request hard control for framework-native actions")
        parser.add_argument("--soft", action="store_true", help="request cooperative control")
        return parser

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Publish a signal and apply framework-native actions when needed."""
        del input_events
        if not args:
            self.parser().print_help()
            return ()
        if args[0] in {"-h", "--help", "help"}:
            self.parser().parse_args(args)
            return ()
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
        completion = control_completion(context, prefix, allow_pipeline=False)
        if completion is not None and (not args or prefix.startswith(("job=", "step=", "serial="))):
            return completion
        if len(args) == 1:
            return [action for action in self.actions if action.startswith(prefix)]
        return [
            candidate
            for candidate in ("target=", "targets=", "host=", "network=", "networks=", "level=", "reason=")
            if candidate.startswith(prefix)
        ]


@commandlet(
    name="end",
    description="Stop a job, pipeline, or pipeline step; defaults to cooperative cancellation.",
    usage="end [--soft|--hard] <job=id|pipeline=id|step=id>",
    examples=("end job=1", "end --hard pipeline=1", "end step=1"),
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
)
@argument("target", "job=<id>, pipeline=<id>, or step=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=", "step=")))
class Stop(Control):
    """Stop a job or pipeline, softly by default."""

    action = "stop"


def plugin() -> Commandlet:
    """Return the first commandlet when loaded as a single plugin entry."""
    return End()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlets provided by this module."""
    return (RuntimeSignal(), End(), Kill(), Cancel(), Pause(), Resume(), Stop())
