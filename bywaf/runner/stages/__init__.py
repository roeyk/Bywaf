"""Pipeline stage execution and commandlet event publishing.

Provides the lifecycle for one pipeline step: input selection, context
construction, argument expansion/redaction, plugin execution, emitted-event
persistence, and child-process stage entry points.

Used by:
- runner.core: runs foreground and background pipeline stages.
- runner jobs: child processes call run_stage_process as their stage entrypoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...command.parser import CommandInvocation
from ...db import EventStore
from ...event import Event
from ...plugin import PipelineStop
from ...registry import PluginRegistry
from ..at_files import expand_at_file_args
from ..context import StageRun, build_context, select_input_events
from ..plans import handle_plan_if_needed
from ..runtime_events import publish_note_if_present, publish_runtime_name, publish_variable_expansion
from .arguments import (
    effective_database_actions,
    normalize_valued_option_args,
    redact_commandlet_args,
    redact_secret_reference_args,
    secret_arg_metadata,
    split_option_arg,
)
from .lifecycle import publish_command_run_arguments, publish_command_run_lifecycle
from .preview import (
    DISPLAY_EXPANSION_DEFAULT,
    DISPLAY_EXPANSION_VAR,
    expansion_display_mode,
    publish_expanded_command_preview,
)

__all__ = [
    "DISPLAY_EXPANSION_DEFAULT",
    "DISPLAY_EXPANSION_VAR",
    "StageResult",
    "effective_database_actions",
    "execute_stage",
    "expansion_display_mode",
    "normalize_valued_option_args",
    "pipeline_visible_stage_events",
    "publish_command_run_arguments",
    "publish_command_run_lifecycle",
    "publish_expanded_command_preview",
    "redact_commandlet_args",
    "redact_secret_reference_args",
    "run_stage_process",
    "secret_arg_metadata",
    "split_option_arg",
]


@dataclass(frozen=True, slots=True)
class StageResult:
    """Events produced by one executed pipeline stage.

    This represents a stage's output events plus optional pipeline-stop state.
    `execute_stage()` returns this after plugin execution.
    `Runner.execute_pipeline()` consumes it to pass events to later pipeline
    stages and honor `PipelineStop` requests without raw tuple state.
    """

    events: list[Event]
    stopped: bool = False
    stop_reason: str = ""


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
    except PipelineStop as exc:
        publish_command_run_lifecycle(context, "completed", emitted=0, stopped=True, reason=exc.reason)
        return StageResult([], stopped=True, stop_reason=exc.reason)
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
