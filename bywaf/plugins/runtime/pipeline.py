"""Runtime pipeline commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Lists and inspects pipeline state and history.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
"""

from __future__ import annotations

import shlex
from argparse import Namespace
from collections.abc import Callable, Iterable

from bywaf.event import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.plugins.runtime.job import cancel_job, kill_job
from bywaf.plugins.runtime.pipeline_view import (
    PIPELINE_SORT_KEYS,
    format_pipeline,
    format_pipeline_artifacts,
    format_pipeline_inspection_hints,
    format_pipeline_jobs,
    format_pipeline_steps,
    print_pipelines,
)
from bywaf.plugins.runtime.view_common import split_since_selector, view_selector_candidates
from bywaf.runtime_display import command_context_style_getter, parse_runtime_list_selectors
from bywaf.style import styled_subject_text

PIPELINE_ACTIONS = ("attach", "cancel", "end", "kill")
REMOVED_PIPELINE_ACTIONS = {"list", "show"}
PipelineActionHandler = Callable[[CommandContext, Namespace], None]

@commandlet(
    name="pipeline",
    description="Manage pipelines.",
    usage="pipeline [--all] [--new] [field=value ...] [since=<id>] | pipeline <id> | pipeline <cancel|end|kill|attach> [options] <id>",
    examples=(
        "pipeline",
        "pipeline --all",
        "pipeline --new",
        "pipeline since=30",
        "pipeline 1",
        "pipeline cancel 1",
        "pipeline end --hard 1",
        "pipeline kill --hard 1",
        "pipeline attach 1 portscanner step=1 since=beginning",
    ),
)
@argument("action", "pipeline operation", required=False, completion=CompletionSpec("choice", PIPELINE_ACTIONS))
@argument("id", "pipeline id", required=False, completion="pipeline")
class Pipeline(CommandletBase):
    """List, inspect, softly cancel, and end pipelines."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify pipeline list/show separately from control and attach."""
        action = next((arg for arg in args if not arg.startswith("--")), "")
        return ("write",) if action in PIPELINE_ACTIONS else ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one pipeline-management operation."""
        parser = self.parser()
        if args and args[0] == "attach":
            # `pipeline attach` has a commandlet tail after its selectors. Parse
            # it separately so commandlet arguments are not mistaken for
            # pipeline-management options.
            attach_pipeline(context, args[1:])
            return ()
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        operation = parse_pipeline_operation(tokens)
        parsed.action = operation.action
        parsed.id = operation.id
        parsed.filters = operation.filters
        parsed.since = operation.since
        parsed.sort = operation.sort
        context.require_foreground("pipeline management commands")
        validate_pipeline_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        pipeline_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and pipeline IDs from the active database."""
        if not args:
            return ["--all", "--new", "--page", "sort=", "since=", *pipeline_ids(context), *PIPELINE_ACTIONS]
        if len(args) == 1 and args[0] == "attach":
            return pipeline_ids(context)
        if len(args) == 1 and args[0] in {"cancel", "end", "kill"}:
            return pipeline_ids(context)
        if args and args[-1].startswith("sort="):
            return view_selector_candidates(args[-1], PIPELINE_SORT_KEYS)
        if len(args) == 1:
            candidates = ["--all", "--new", "--page", "sort=", "since=", *pipeline_ids(context), *PIPELINE_ACTIONS]
            candidates.extend(view_selector_candidates(prefix, PIPELINE_SORT_KEYS))
            return [candidate for candidate in candidates if candidate.startswith(prefix)]
        if args and args[0] == "attach":
            return attach_candidates(context, args, prefix)
        if len(args) >= 2 and args[0] in {"cancel", "end", "kill"}:
            return pipeline_ids(context)
        return []


def parse_pipeline_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `pipeline` forms into the internal action/id/filter shape."""
    if not tokens:
        return Namespace(action="list", id=None, filters={}, since="", sort="")
    first, rest = tokens[0], tokens[1:]
    if first in REMOVED_PIPELINE_ACTIONS:
        raise ValueError(
            "usage: pipeline [--all] [field=value ...] | pipeline <id> | pipeline <cancel|end|kill|attach> [options] <id>"
        )
    if first in {"cancel", "end", "kill"}:
        if not rest:
            raise ValueError(f"pipeline {first} requires a pipeline id")
        selectors, since = split_since_selector("pipeline", rest[1:])
        filters, sort = parse_runtime_list_selectors(selectors, allowed_sort_keys=PIPELINE_SORT_KEYS, command="pipeline")
        return Namespace(action=first, id=rest[0], filters=filters, since=since, sort=sort)
    if "=" not in first and not rest:
        return Namespace(action="show", id=first, filters={}, since="", sort="")
    selectors, since = split_since_selector("pipeline", tokens)
    filters, sort = parse_runtime_list_selectors(selectors, allowed_sort_keys=PIPELINE_SORT_KEYS, command="pipeline")
    return Namespace(action="list", id=None, filters=filters, since=since, sort=sort)


def pipeline_action_handlers() -> dict[str, PipelineActionHandler]:
    """Return pipeline action handlers keyed by action name."""
    return {
        "cancel": cancel_pipeline_action,
        "end": end_pipeline_action,
        "kill": end_pipeline_action,
        "list": list_pipeline_action,
        "show": show_pipeline_action,
    }


def list_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline list`."""
    print_pipelines(
        context,
        active_only=False,
        show_active=parsed.all,
        page=parsed.page,
        filters=parsed.filters,
        highlight_newest=parsed.new,
        since=parsed.since,
        sort_key=parsed.sort,
    )


def show_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline show`."""
    row = require_pipeline(context, parsed.id)
    runtime = context.runtime_store("pipeline show")
    display_name = runtime.runtime_names().get(("pipeline", str(row["pipeline_id"])))
    alias = runtime.pipeline_aliases().get(str(row["pipeline_id"]))
    style_getter = command_context_style_getter(context)
    sections = [
        format_pipeline(
            row,
            display_name=display_name,
            alias=alias,
            style_getter=style_getter,
        ),
        format_pipeline_inspection_hints(context, str(row["pipeline_id"])),
        format_pipeline_artifacts(context, str(row["pipeline_id"]), alias or str(row["pipeline_id"])),
        format_pipeline_jobs(context, str(row["pipeline_id"])),
        format_pipeline_steps(context, str(row["pipeline_id"])),
    ]
    context.output("\n\n".join(section for section in sections if section))

def cancel_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline cancel`."""
    cancel_pipeline(context, parsed.id)


def end_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline end` or `pipeline kill`."""
    if parsed.hard:
        kill_pipeline(context, parsed.id)
    else:
        cancel_pipeline(context, parsed.id)

def validate_pipeline_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for pipeline management operations."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("pipeline cancel is already cooperative; use pipeline end --hard or pipeline kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"pipeline {action} does not accept --soft or --hard")

def require_pipeline(context: CommandContext, pipeline_id: str | None):
    """Return a pipeline row or raise a user-facing error."""
    if not pipeline_id:
        raise ValueError("pipeline id is required")
    runtime = context.runtime_store("pipeline")
    resolved = runtime.resolve_pipeline_serial(pipeline_id)
    for row in runtime.pipelines():
        if row["pipeline_id"] == resolved:
            return row
    raise ValueError(f"unknown pipeline: {pipeline_id}")


def cancel_pipeline(context: CommandContext, pipeline_id: str | None) -> None:
    """Request cooperative cancellation for a pipeline and its known jobs."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    runtime = context.runtime_store("pipeline cancel")
    runtime.request_cancellation("pipeline", row["pipeline_id"])
    for job in runtime.jobs_for_pipeline(row["pipeline_id"]):
        cancel_job(context, job)
    context.output(f"cancel requested for pipeline {row['pipeline_id']}")


def kill_pipeline(context: CommandContext, pipeline_id: str | None) -> None:
    """Hard-kill known jobs associated with a pipeline."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    jobs = context.runtime_store("pipeline kill").jobs_for_pipeline(row["pipeline_id"])
    if not jobs:
        raise ValueError(f"pipeline {row['pipeline_id']} has no associated jobs")
    for job in jobs:
        kill_job(context, job)
    context.output(f"killed pipeline {row['pipeline_id']}")


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


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Pipeline()
