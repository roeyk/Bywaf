"""Runtime artifact commandlets.

Provides bundled commandlet metadata and dispatch for artifact management while
delegating parsing, selection, rendering, and storage actions to focused helper
modules.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute artifact and search through normal dispatch.
- tests and bundle code: import stable helper exports from this module."""

from __future__ import annotations

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

from .command.completion import (
    action_or_selector_candidates,
    artifact_completion_selectors as artifact_completion_selectors,
    artifact_selector_completion as artifact_selector_completion,
    search_completion_candidates,
)
from .command.handlers import artifact_action_handlers as artifact_action_handlers
from .common import ARTIFACT_ACTIONS, SEARCH_FIELDS, SEARCH_FLAGS
from .query import (
    filter_artifact_time_window as filter_artifact_time_window,
    search_artifacts,
    select_artifacts as select_artifacts,
)
from .render import artifact_event_payload as artifact_event_payload, format_artifact_row
from .selectors import parse_search_selectors


@commandlet(
    name="artifact",
    description="Import, attach, cat, show, list, export, replace, remove, and verify artifacts.",
    usage="artifact <import|attach|cat|show|list|export|replace|remove|search|verify> [serial=id|artifact=id|step=id|pipeline=id|job=id|topic=name] [file=path|dir=path]",
    examples=(
        "artifact attach step=1 file=snapshot.html name='Landing page'",
        "artifact attach serial=run-... file=snapshot.html",
        "artifact import file=snapshot.html name='Landing page'",
        "artifact attach artifact=1 step=1",
        "artifact cat artifact=1",
        "artifact cat 1 limit=4096",
        "artifact show artifact=1",
        "artifact list step=1",
        "artifact search --regexp note='login|cookie'",
        "artifact replace artifact=1 file=snapshot-v2.html",
        "artifact remove artifact=1",
        "artifact export artifact=1 file=snapshot.html",
        "artifact export step=1 dir=artifacts/",
        "artifact verify pipeline=1",
    ),
)
@argument("action", "artifact action", completion=CompletionSpec("choice", ARTIFACT_ACTIONS))
@argument("selector", "serial=, artifact=, step=, pipeline=, job=, file=, dir=, name=, or note=", required=False)
class ArtifactCommand(CommandletBase):
    """Manage artifacts linked to Bywaf runtime entities."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify artifact inspection separately from artifact mutation."""
        action = args[0] if args else ""
        return ("view",) if action in {"cat", "list", "search", "show", "verify"} else ("write",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Execute one artifact action."""
        del input_events
        if not args:
            raise ValueError("artifact requires an action: import, attach, cat, export, list, remove, replace, search, show, or verify")
        action, *tokens = args
        handler = artifact_action_handlers().get(action)
        if handler is None:
            raise ValueError(f"unknown artifact action: {action}")
        handler(context, tokens)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete actions first, then selectors and filesystem paths."""
        return action_or_selector_candidates(context, args, prefix)


@commandlet(
    name="search",
    description="Search artifact metadata and text content.",
    usage="search [--regexp] <name=text|filename=text|note=text|content=text|serial=id> [artifact=id|step=id|pipeline=id|job=id] [since=time|until=time]",
    examples=(
        "search name=landing",
        "search --regexp filename='.*\\.png'",
        "search serial=pipeline-...",
        "search step=1 content=csrf",
    ),
)
@argument("query", "name=, filename=, note=, or content= query text", required=False)
@argument("regexp", "--regexp treats query values as Python regular expressions", required=False, completion=CompletionSpec("choice", SEARCH_FLAGS))
class SearchCommand(CommandletBase):
    """Search artifact metadata without changing artifacts."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Search only inspects artifact metadata."""
        del args
        return ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Search artifact metadata and print matching artifact rows."""
        del input_events
        selectors = parse_search_selectors(args)
        if not any(field in selectors for field in SEARCH_FIELDS) and "serial" not in selectors:
            raise ValueError("search requires name=, filename=, note=, content=, or serial=")
        artifacts = search_artifacts(context, selectors)
        if not artifacts:
            context.output("no artifacts matched")
            return ()
        for artifact in artifacts:
            context.output(format_artifact_row(artifact))
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete search selectors, scopes, and runtime entity ids."""
        del args
        return search_completion_candidates(context, prefix)


def plugins() -> tuple[Commandlet, ...]:
    """Return artifact management and search commandlets."""
    return ArtifactCommand(), SearchCommand()
