"""Runtime pipeline commandlet.

Provides the bundled `runtime.pipeline` plugin implementation and CommandSpec
metadata. Operators use this commandlet to list, inspect, attach to, and
control pipelines.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
- Runtime control plugins: import the re-exported pipeline control helpers.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable

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
from bywaf.plugins.runtime.pipeline.actions import (
    cancel_pipeline,
    kill_pipeline,
    pipeline_action_handlers,
    require_pipeline,
    validate_pipeline_mode,
)
from bywaf.plugins.runtime.pipeline.attach import attach_candidates, attach_pipeline, pipeline_ids
from bywaf.plugins.runtime.pipeline.view import PIPELINE_SORT_KEYS
from bywaf.plugins.runtime.view_common import split_since_selector, view_selector_candidates
from bywaf.runtime_display import parse_runtime_list_selectors

PIPELINE_ACTIONS = ("attach", "cancel", "end", "kill")
REMOVED_PIPELINE_ACTIONS = {"list", "show"}

__all__ = [
    "PIPELINE_ACTIONS",
    "PIPELINE_SORT_KEYS",
    "Pipeline",
    "attach_pipeline",
    "cancel_pipeline",
    "kill_pipeline",
    "parse_pipeline_operation",
    "pipeline_ids",
    "plugin",
    "require_pipeline",
    "validate_pipeline_mode",
]


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
        del input_events
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
        # `pipeline_action_handlers()` returns the action dispatch table used
        # here instead of an if/elif ladder over list/show/cancel/end/kill.
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


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Pipeline()
