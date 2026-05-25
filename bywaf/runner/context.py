"""Stage preparation and command context construction.

Provides stage run identity, input event selection, variable snapshots, and
CommandContext construction for runner execution.

Used by:
- runner.core: prepares stages and contexts before plugin execution.
- background job helpers: carry stage identity into child processes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..command_parser import CommandInvocation
from ..db import EventStore
from ..events import Event
from ..plugin import CommandContext, implied_capabilities
from ..registry import PluginRegistry
from ..varstore import VarStore


def new_run_id(prefix: str) -> str:
    """Return a readable unique ID suitable for DB scope fields."""
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    return f"{safe_prefix}-{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class StageRun:
    """Execution identity assigned to one pipeline stage."""

    invocation: CommandInvocation
    command_run_id: str
    parent_command_run_id: str | None


def select_input_events(
    db: EventStore,
    invocation: CommandInvocation,
    fallback_events: list[Event],
) -> list[Event]:
    """Choose pipeline input events or DB-selected events for one invocation."""
    if not any((invocation.from_run, invocation.from_pipeline, invocation.from_topic)):
        return fallback_events
    return db.events_matching(
        command_run_id=db.resolve_run_serial(invocation.from_run) if invocation.from_run else None,
        pipeline_id=db.resolve_pipeline_serial(invocation.from_pipeline) if invocation.from_pipeline else None,
        topic=invocation.from_topic,
        after_id=invocation.replay_after_id,
    )


def prepare_stage_runs(commands: tuple[CommandInvocation, ...]) -> tuple[StageRun, ...]:
    """Assign stable run IDs and upstream parent IDs to pipeline stages."""
    stages: list[StageRun] = []
    parent_id: str | None = None
    for invocation in commands:
        command_run_id = new_run_id(invocation.name)
        stages.append(StageRun(invocation, command_run_id, parent_id))
        parent_id = command_run_id
    return tuple(stages)


def is_management_pipeline(commands: tuple[CommandInvocation, ...]) -> bool:
    """Return True for foreground management commands that should run directly."""
    return len(commands) == 1 and commands[0].name in {"db", "job", "pipeline"}


def effective_run_vars(varstore: VarStore, commandlet: str) -> dict[str, str]:
    """Return the session variables visible to one commandlet at launch time."""
    prefix = f"{commandlet}."
    provider_prefix = f"{provider_scope_for_commandlet_scope(commandlet)}."
    return {
        key: value
        for key, value in varstore.items()
        if key.startswith(prefix) or key.startswith(provider_prefix) or key.startswith("global.")
    }


def provider_scope_for_commandlet_scope(commandlet: str) -> str:
    """Return provider scope for one commandlet variable scope."""
    if "/" not in commandlet:
        return commandlet
    return commandlet.rsplit("/", 1)[0]


def ensure_run_var_snapshot(
    db: EventStore,
    varstore: VarStore,
    *,
    job_id: int | None,
    pipeline_id: str,
    command_run_id: str,
    commandlet: str,
) -> dict[str, str]:
    """Load or create the immutable variable snapshot for one command run."""
    existing = db.command_run_vars(command_run_id)
    if existing:
        return existing
    values = effective_run_vars(varstore, commandlet)
    db.record_command_run_vars(
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        commandlet=commandlet,
        values=values,
    )
    return values


def build_context(
    db: EventStore,
    registry: PluginRegistry,
    stage: StageRun,
    *,
    pipeline_id: str,
    job_id: int | None,
    input_high_watermark: int,
    replace_db,
    runner=None,
) -> CommandContext:
    """Build the runtime context for one commandlet stage."""
    invocation = stage.invocation
    plugin = registry.get(invocation.name)
    variable_scope = registry.variable_scope(invocation.name)
    provider_scope = provider_scope_for_commandlet_scope(variable_scope)
    run_vars = ensure_run_var_snapshot(
        db,
        registry.varstore,
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=stage.command_run_id,
        commandlet=variable_scope,
    )
    return CommandContext(
        db,
        source=plugin.spec.name,
        _varstore=registry.varstore,
        _secrets=registry.secrets,
        metadata={
            "pipeline_id": pipeline_id,
            "command_run_id": stage.command_run_id,
            "parent_command_run_id": stage.parent_command_run_id,
            "input_high_watermark": input_high_watermark,
            "var_scope": variable_scope,
            "provider_scope": provider_scope,
            "provider_variables": (*plugin.spec.provider_variables, *plugin.spec.secret_provider_variables),
            "background": invocation.background,
            "from_run": invocation.from_run,
            "from_pipeline": invocation.from_pipeline,
            "from_topic": invocation.from_topic,
            "note": invocation.note,
            "replace_db": replace_db,
            "runner": runner,
            "job_id": job_id,
            "run_vars": run_vars,
            "capabilities": implied_capabilities(plugin.spec),
        },
    )
