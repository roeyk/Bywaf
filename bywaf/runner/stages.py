"""Pipeline stage execution and commandlet event publishing.

Provides the lifecycle for one pipeline step: input selection, context
construction, argument expansion/redaction, plugin execution, emitted-event
persistence, and child-process stage entry points.

Used by:
- runner.core: runs foreground and background pipeline stages.
- runner jobs: child processes call run_stage_process as their stage entrypoint.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..command.parser import CommandInvocation
from ..db import EventStore
from ..event import Event
from ..plugin import CommandContext
from ..plugin.capabilities import DATABASE_ACTIONS
from ..registry import PluginRegistry
from ..secret.store import REDACTED_VALUE, fingerprint_secret, load_or_create_fingerprint_key
from .at_files import expand_at_file_args
from .context import StageRun, build_context, select_input_events
from .plans import handle_plan_if_needed
from .runtime_events import publish_note_if_present, publish_runtime_name, publish_variable_expansion


@dataclass(frozen=True, slots=True)
class StageResult:
    """Events produced by one executed pipeline stage."""

    events: list[Event]


def execute_stage(
    db: EventStore,
    registry: PluginRegistry,
    stage: StageRun,
    *,
    pipeline_id: str,
    job_id: int | None,
    input_events: list[Event],
    replace_db=None,
    runner=None,
) -> StageResult:
    """Execute one pipeline stage and persist yielded payloads as events."""
    invocation = stage.invocation
    plugin = registry.get(invocation.name)
    selected_input_events = select_input_events(db, invocation, input_events)
    input_high_watermark = max(
        (event.id or 0 for event in selected_input_events),
        default=invocation.replay_after_id,
    )
    context = build_context(
        db,
        registry,
        stage,
        pipeline_id=pipeline_id,
        job_id=job_id,
        input_high_watermark=input_high_watermark,
        replace_db=replace_db,
        runner=runner,
    )
    context.raise_if_cancelled()
    stage_start_event_id = db.latest_event_id()
    publish_command_run_lifecycle(context, "started")
    publish_note_if_present(db, context, invocation.note)
    try:
        if invocation.display_name:
            publish_runtime_name(
                db,
                "run",
                stage.command_run_id,
                invocation.display_name,
                job_id=job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                parent_command_run_id=stage.parent_command_run_id,
            )
        publish_variable_expansion(context, invocation.variable_expansions)
        expanded_args = expand_at_file_args(context, invocation.args)
        planned_args = handle_plan_if_needed(context, plugin, expanded_args, selected_input_events, invocation)
        if planned_args is None:
            publish_command_run_lifecycle(context, "completed", emitted=0, skipped=True)
            return StageResult([])
        expanded_args = normalize_valued_option_args(plugin, planned_args)
        publish_expanded_command_preview(context, invocation, plugin, expanded_args)
        publish_command_run_arguments(context, plugin, expanded_args)
        for input_topic in sorted({event.topic for event in selected_input_events}):
            context.audit_capability(f"db.read:{input_topic}")
        topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
        yielded_events = []
        for payload in plugin.run(context, expanded_args, selected_input_events):
            context.audit_capability(f"db.write:{topic}")
            yielded_events.append(
                db.publish(
                    topic,
                    payload,
                    plugin.spec.name,
                    pipeline_id=pipeline_id,
                    command_run_id=stage.command_run_id,
                    parent_command_run_id=stage.parent_command_run_id,
                )
            )
        events = pipeline_visible_stage_events(
            db,
            plugin.spec.emits,
            stage.command_run_id,
            after_id=stage_start_event_id,
            yielded_events=yielded_events,
        )
        publish_command_run_lifecycle(context, "completed", emitted=len(events))
        return StageResult(events)
    except Exception as exc:
        publish_command_run_lifecycle(context, "failed", error=str(exc), exception=exc.__class__.__name__)
        raise


def pipeline_visible_stage_events(
    db: EventStore,
    emitted_topics: tuple[str, ...],
    command_run_id: str,
    *,
    after_id: int,
    yielded_events: list[Event],
) -> list[Event]:
    """Return events from this stage that should feed the next pipeline stage."""
    if not emitted_topics:
        return yielded_events
    emitted = set(emitted_topics)
    direct_events = [
        event
        for event in db.events_matching(command_run_id=command_run_id, after_id=after_id, limit=10000)
        if event.topic in emitted
    ]
    by_id: dict[int, Event] = {}
    unsaved: list[Event] = []
    for event in [*yielded_events, *direct_events]:
        if event.id is None:
            unsaved.append(event)
            continue
        by_id[event.id] = event
    return [*unsaved, *[by_id[event_id] for event_id in sorted(by_id)]]


def normalize_valued_option_args(plugin, args: list[str]) -> list[str]:
    """Convert public `name=value` syntax into argparse `--name value` pairs."""
    valued_options = {option.name for option in plugin.spec.options if option.name not in {"listen", "silent"}}
    normalized: list[str] = []
    for arg in args:
        if "=" not in arg or arg.startswith("--"):
            normalized.append(arg)
            continue
        key, value = arg.split("=", 1)
        if key not in valued_options:
            normalized.append(arg)
            continue
        normalized.extend((f"--{key}", value))
    return normalized


DISPLAY_EXPANSION_VAR = "display.expansion"
DISPLAY_EXPANSION_DEFAULT = "off"


def publish_expanded_command_preview(
    context: CommandContext,
    invocation: CommandInvocation,
    plugin,
    args: list[str],
) -> Event | None:
    """Print an optional redacted preview of the expanded command line."""
    mode = expansion_display_mode(context)
    if mode == "off" or context._db is None:
        return None
    if mode == "changed" and not invocation.expanded_text:
        return None
    redacted_args, _secret_args = redact_commandlet_args(context, plugin, args)
    redacted_args = redact_secret_reference_args(context, redacted_args)
    text = f"expanded: {invocation.name}"
    if redacted_args:
        text = f"{text} {' '.join(shlex.quote(arg) for arg in redacted_args)}"
    return context._db.publish(
        "framework.console.output.requested",
        {"text": f"{text}\n", "end": ""},
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def redact_secret_reference_args(context: CommandContext, args: list[str]) -> list[str]:
    """Redact expanded args that are direct secret references."""
    redacted: list[str] = []
    for arg in args:
        if context._secrets.metadata(arg) is not None:
            redacted.append(REDACTED_VALUE)
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            if context._secrets.metadata(value) is not None:
                redacted.append(f"{key}={REDACTED_VALUE}")
                continue
        redacted.append(arg)
    return redacted


def expansion_display_mode(context: CommandContext) -> str:
    """Return normalized command expansion preview mode."""
    run_vars = context.metadata.get("run_vars", {})
    value = (
        run_vars.get(DISPLAY_EXPANSION_VAR, DISPLAY_EXPANSION_DEFAULT)
        if isinstance(run_vars, dict)
        else DISPLAY_EXPANSION_DEFAULT
    )
    mode = str(value or DISPLAY_EXPANSION_DEFAULT).strip().casefold()
    if mode in {"off", "changed", "on"}:
        return mode
    return DISPLAY_EXPANSION_DEFAULT


def publish_command_run_lifecycle(context: CommandContext, status: str, **details: object) -> Event | None:
    """Publish pipeline-step lifecycle events used by finite listeners."""
    if context._db is None:
        return None
    payload = {
        "status": status,
        "commandlet": context.source,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "parent_command_run_id": context.parent_command_run_id,
    }
    payload.update(details)
    return context._db.publish(
        f"command.run.{status}",
        payload,
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_command_run_arguments(context: CommandContext, plugin, args: list[str]) -> Event | None:
    """Publish commandlet arguments after framework expansion/redaction."""
    if context._db is None:
        return None
    redacted_args, secret_args = redact_commandlet_args(context, plugin, args)
    return context._db.publish(
        "command.run.arguments",
        {
            "commandlet": context.source,
            "args": redacted_args,
            "secret_args": secret_args,
            "database_actions": list(effective_database_actions(plugin, args)),
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "parent_command_run_id": context.parent_command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def effective_database_actions(plugin, args: list[str]) -> tuple[str, ...]:
    """Return the effective DB action class for this commandlet invocation."""
    classifier = getattr(plugin, "database_actions_for_args", None)
    actions: Iterable[str] = (
        cast(Iterable[str], classifier(args))
        if callable(classifier)
        else plugin.spec.database_actions
    )
    seen: set[str] = set()
    normalized: list[str] = []
    for action in actions:
        value = str(action)
        if value not in DATABASE_ACTIONS:
            raise ValueError(f"{plugin.spec.name} returned unknown database action: {value}")
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return tuple(action for action in DATABASE_ACTIONS if action in seen) if normalized else tuple()


def redact_commandlet_args(context: CommandContext, plugin, args: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Redact declared secret commandlet options while preserving provenance."""
    secret_options = {option.name.strip().lower().replace("_", "-") for option in plugin.spec.options if option.secret}
    if not secret_options:
        return list(args), []
    redacted: list[str] = []
    secrets: list[dict[str, str]] = []
    pending_secret_option: str | None = None
    for arg in args:
        if pending_secret_option is not None:
            redacted.append(REDACTED_VALUE)
            secrets.append(secret_arg_metadata(context, pending_secret_option, arg))
            pending_secret_option = None
            continue
        option_name, value, style = split_option_arg(arg)
        if option_name is not None and option_name in secret_options:
            if value is None:
                redacted.append(f"--{option_name}")
                pending_secret_option = option_name
                continue
            secrets.append(secret_arg_metadata(context, option_name, value))
            redacted.append(f"--{option_name}={REDACTED_VALUE}" if style == "long-equals" else f"{option_name}={REDACTED_VALUE}")
            continue
        redacted.append(arg)
    return redacted, secrets


def split_option_arg(arg: str) -> tuple[str | None, str | None, str]:
    """Return normalized option name/value/style for long options and key=value."""
    if arg.startswith("--") and "=" in arg:
        key, value = arg[2:].split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "long-equals"
    if arg.startswith("--"):
        return arg[2:].strip().lower().replace("_", "-"), None, "long"
    if "=" in arg:
        key, value = arg.split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "key-equals"
    return None, None, ""


def secret_arg_metadata(context: CommandContext, name: str, value: str) -> dict[str, str]:
    """Return audit-safe metadata for one secret argument value."""
    secret_ref = context._secrets.metadata(value)
    if secret_ref is not None:
        return {"name": secret_ref.name, "option": name, "fingerprint": secret_ref.fingerprint.format()}
    return {
        "name": name,
        "option": name,
        "fingerprint": fingerprint_secret(value, load_or_create_fingerprint_key()).format(),
    }


def run_stage_process(
    db_path: str,
    db_passphrase: str | None,
    job_id: int | None,
    name: str,
    args: list[str],
    pipeline_id: str,
    command_run_id: str,
    parent_command_run_id: str | None,
    background: bool,
    from_step: str | None,
    from_pipeline: str | None,
    from_job: str | None,
    from_topic: str | None,
    replay_after_id: int,
    note: str | None,
    display_name: str | None,
    variable_expansions: tuple[str, ...],
    expanded_text: str | None,
    plan_only: bool,
    approved: bool,
) -> None:
    """Child-process entry point for one background pipeline stage."""
    db = EventStore(Path(db_path), passphrase=db_passphrase)
    registry = PluginRegistry.discover()
    stage = StageRun(
        CommandInvocation(
            name,
            args,
            background=background,
            from_step=from_step,
            from_pipeline=from_pipeline,
            from_job=from_job,
            from_topic=from_topic,
            replay_after_id=replay_after_id,
            note=note,
            display_name=display_name,
            variable_expansions=variable_expansions,
            expanded_text=expanded_text,
            plan_only=plan_only,
            approved=approved,
        ),
        command_run_id,
        parent_command_run_id,
    )
    execute_stage(db, registry, stage, pipeline_id=pipeline_id, job_id=job_id, input_events=[])
