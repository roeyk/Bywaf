"""Runner expanded-command preview publisher.

Used by: `runner.stages.execute_stage()` when `display.expansion` asks the
framework to show a redacted expanded command line before plugin execution.
"""

from __future__ import annotations

import shlex

from ...command.parser import CommandInvocation
from ...event import Event
from ...plugin import CommandContext
from .arguments import redact_commandlet_args, redact_secret_reference_args

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
