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
from bywaf.utils import complete_path

from .actions import (
    attach_artifacts,
    cat_artifact,
    export_artifacts,
    import_artifacts,
    list_artifacts,
    remove_artifacts,
    replace_artifact,
    search_artifact_command as run_artifact_search,
    show_artifact,
    verify_artifacts,
)
from .common import ARTIFACT_ACTIONS, SEARCH_FIELDS, SEARCH_FLAGS, ArtifactActionHandler
from .completion import artifact_ids, artifact_topics, job_ids, pipeline_ids, run_ids, serial_ids
from .query import (
    filter_artifact_time_window as filter_artifact_time_window,
    search_artifacts,
    select_artifacts as select_artifacts,
)
from .render import artifact_event_payload as artifact_event_payload, format_artifact_row
from .selectors import parse_artifact_cat_selectors, parse_artifact_selectors, parse_search_selectors, pop_page_flag


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
    capabilities=(
        "artifact.read",
        "artifact.write",
        "db.read:artifact.attached",
        "filesystem.read",
        "filesystem.write",
        "framework.console.output",
        "framework.file.page",
    ),
    database_actions=("view", "write"),
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
        if not args:
            return list(ARTIFACT_ACTIONS)
        if len(args) == 1 and args[0] not in ARTIFACT_ACTIONS:
            return [action for action in ARTIFACT_ACTIONS if action.startswith(prefix)]
        completion = artifact_selector_completion(context, prefix)
        if completion is not None:
            return completion
        return artifact_completion_selectors().get(args[0], list(ARTIFACT_ACTIONS))


def artifact_action_handlers() -> dict[str, ArtifactActionHandler]:
    """Return artifact action handlers keyed by action name."""
    return {
        "attach": attach_artifacts_command,
        "cat": cat_artifact_command,
        "list": list_artifacts_command,
        "import": import_artifacts_command,
        "remove": remove_artifacts_command,
        "replace": replace_artifact_command,
        "export": export_artifacts_command,
        "search": search_artifact_command,
        "show": show_artifact_command,
        "verify": verify_artifacts_command,
    }


def artifact_completion_selectors() -> dict[str, list[str]]:
    """Return selector completions keyed by artifact action."""
    return {
        "attach": ["artifact=", "serial=", "step=", "pipeline=", "job=", "file=", "name=", "note="],
        "import": ["file=", "name=", "note="],
        "cat": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "limit=", "encoding=", "--page"],
        "replace": ["artifact=", "file=", "name=", "note="],
        "remove": ["artifact=", "serial=", "step=", "pipeline=", "job="],
        "list": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "--page"],
        "show": ["artifact=", "serial="],
        "verify": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic="],
        "export": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "file=", "dir="],
        "search": [
            "name=",
            "filename=",
            "note=",
            "content=",
            "serial=",
            "--regexp",
            "artifact=",
            "step=",
            "pipeline=",
            "job=",
            "since=",
            "until=",
        ],
    }


def artifact_selector_completion(context: CompletionContext, prefix: str) -> list[str] | None:
    """Complete common artifact selectors and filesystem paths."""
    if prefix.startswith("file="):
        return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
    if prefix.startswith("dir="):
        return [f"dir={candidate}" for candidate in complete_path(prefix.removeprefix("dir="))]
    if prefix.startswith("step="):
        return [f"step={value}" for value in run_ids(context)]
    if prefix.startswith("pipeline="):
        return [f"pipeline={value}" for value in pipeline_ids(context)]
    if prefix.startswith("job="):
        return [f"job={value}" for value in job_ids(context)]
    if prefix.startswith("artifact="):
        return [f"artifact={value}" for value in artifact_ids(context)]
    if prefix.startswith("serial="):
        return [f"serial={value}" for value in serial_ids(context)]
    if prefix.startswith("topic="):
        return [f"topic={value}" for value in artifact_topics(context)]
    return None


def attach_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact attach."""
    attach_artifacts(context, parse_artifact_selectors(tokens))


def import_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact import."""
    import_artifacts(context, parse_artifact_selectors(tokens))


def list_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact list."""
    selectors = parse_artifact_selectors(tokens, allow_page=True)
    list_artifacts(context, selectors, page=pop_page_flag(selectors))


def show_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact show."""
    if len(tokens) == 1 and "=" not in tokens[0]:
        tokens = [f"artifact={tokens[0]}"]
    show_artifact(context, parse_artifact_selectors(tokens))


def cat_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact cat."""
    if tokens and "=" not in tokens[0] and not tokens[0].startswith("--"):
        tokens = [f"artifact={tokens[0]}", *tokens[1:]]
    cat_artifact(context, parse_artifact_cat_selectors(tokens))


def remove_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact remove."""
    remove_artifacts(context, parse_artifact_selectors(tokens))


def replace_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact replace."""
    replace_artifact(context, parse_artifact_selectors(tokens))


def export_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact export."""
    export_artifacts(context, parse_artifact_selectors(tokens))


def verify_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact verify."""
    verify_artifacts(context, parse_artifact_selectors(tokens))


def search_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact metadata search."""
    selectors = parse_search_selectors(tokens)
    if not any(field in selectors for field in SEARCH_FIELDS) and "serial" not in selectors:
        raise ValueError("artifact search requires name=, filename=, note=, content=, or serial=")
    run_artifact_search(context, selectors)


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
    capabilities=(
        "artifact.read",
        "framework.console.output",
    ),
    database_actions=("view",),
)
@argument("query", "name=, filename=, note=, or content= query text", required=False)
@argument("regexp", "--regexp treats query values as Python regular expressions", required=False, completion=CompletionSpec("choice", SEARCH_FLAGS))
class SearchCommand(CommandletBase):
    """Search artifact metadata without changing artifacts."""

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
        completion = artifact_selector_completion(context, prefix)
        if completion is not None:
            return completion
        return ["name=", "filename=", "note=", "content=", "serial=", "--regexp", "artifact=", "step=", "pipeline=", "job=", "since=", "until="]


def plugins() -> tuple[Commandlet, ...]:
    """Return artifact management and search commandlets."""
    return ArtifactCommand(), SearchCommand()
