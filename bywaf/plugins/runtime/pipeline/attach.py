"""Pipeline attach and completion helpers.

Used by: `runtime.pipeline.Pipeline` for `pipeline attach ...` execution and
runtime-aware pipeline/step completion.
"""

from __future__ import annotations

import shlex

from bywaf.plugin import CommandContext, CompletionContext
from bywaf.runtime_display import command_context_style_getter
from bywaf.style import styled_subject_text


def attach_pipeline(context: CommandContext, args: list[str]) -> None:
    """Attach one commandlet to an existing pipeline as a background job."""
    context.require_foreground("pipeline attach")
    if len(args) < 2:
        raise ValueError("usage: pipeline attach <pipeline-id> <commandlet> [step=<step-id>] [since=beginning|now] [args...]")
    pipeline_id, commandlet_name, *tail = args
    runtime = context.runtime_store("pipeline attach")
    resolved_pipeline_id = runtime.resolve_pipeline_serial(pipeline_id)
    selectors, commandlet_args = parse_attach_tail(tail)
    runner = context.metadata.get("runner")
    if runner is None:
        raise ValueError("pipeline attach requires a live runner")
    command_line = " ".join(shlex.quote(token) for token in [commandlet_name, *commandlet_args])
    # The runner owns the attached background execution so it can replay prior
    # pipeline events from the requested cursor and keep runtime metadata stable.
    event = runner.start_attached_pipeline(
        resolved_pipeline_id,
        command_line,
        upstream_run_id=(
            runtime.resolve_run_serial(selectors["step"]) if "step" in selectors else None
        ),
        since_cursor=selectors.get("since", "beginning"),
    )
    shown_command = styled_subject_text(command_context_style_getter(context), "command_line", command_line)
    context.output(f"attached job={event.payload['job_id']} pipeline={resolved_pipeline_id} command={shown_command}")


def parse_attach_tail(tokens: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split attach selectors from commandlet arguments."""
    selectors: dict[str, str] = {}
    commandlet_args: list[str] = []
    for token in tokens:
        # Only these selectors belong to pipeline attach. Everything else is
        # passed through verbatim to the commandlet being attached.
        if token.startswith("step="):
            selectors["step"] = require_selector_value(token)
        elif token.startswith("since="):
            value = require_selector_value(token)
            if value not in {"beginning", "now"}:
                raise ValueError("since= must be beginning or now")
            selectors["since"] = value
        else:
            commandlet_args.append(token)
    return selectors, commandlet_args


def require_selector_value(token: str) -> str:
    """Return the value from a non-empty key=value selector."""
    _key, value = token.split("=", 1)
    if not value:
        raise ValueError(f"{token} requires a value")
    return value


def attach_candidates(context: CompletionContext, args: list[str], prefix: str) -> list[str]:
    """Complete attach pipeline id, commandlet name, and attach selectors."""
    if len(args) == 2:
        return pipeline_ids(context)
    if len(args) == 3:
        names = context.metadata.get("commandlets", ())
        return [name for name in names if str(name).startswith(prefix)]
    if prefix.startswith("step="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"step={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
    if prefix.startswith("since="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"since={value}" for value in ("beginning", "now") if value.startswith(value_prefix)]
    return ["step=", "since="]


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    try:
        runtime = context.runtime_store("pipeline completion")
    except ValueError:
        return []
    return sorted(runtime.pipeline_aliases().values(), key=int)


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    try:
        runtime = context.runtime_store("pipeline completion")
    except ValueError:
        return []
    return sorted(runtime.run_aliases().values(), key=int)
