"""Artifact command dispatch wrappers.

Used by: `runtime.artifact.ArtifactCommand.run()` to parse action-specific
selector tokens before delegating to storage/display action helpers.
"""

from __future__ import annotations

from bywaf.plugin import CommandContext

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
from .common import SEARCH_FIELDS, ArtifactActionHandler
from .selectors import parse_artifact_cat_selectors, parse_artifact_selectors, parse_search_selectors, pop_page_flag


def artifact_action_handlers() -> dict[str, ArtifactActionHandler]:
    """Return artifact action handlers keyed by action name."""
    # ArtifactCommand.run() uses this dispatch table instead of an if/elif
    # ladder over action names.
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
