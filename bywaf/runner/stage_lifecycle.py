"""Runner command-run lifecycle event publishers.

Used by: `runner.stages.execute_stage()` to persist stage start/completion,
failure, and argument audit events around commandlet execution.
"""

from __future__ import annotations

from ..event import Event
from ..plugin import CommandContext
from .stage_arguments import effective_database_actions, redact_commandlet_args


def publish_command_run_lifecycle(context: CommandContext, status: str, **details: object) -> Event | None:
    """Publish pipeline-step lifecycle events used by finite listeners."""
    if context._db is None:
        return None
    payload = {
        "status": status,
        "commandlet": context.source,
        "plugin_version": context.metadata.get("plugin_version"),
        "requires_bywaf": context.metadata.get("requires_bywaf"),
        "bywaf_version": context.metadata.get("bywaf_version"),
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
            "plugin_version": context.metadata.get("plugin_version"),
            "requires_bywaf": context.metadata.get("requires_bywaf"),
            "bywaf_version": context.metadata.get("bywaf_version"),
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
