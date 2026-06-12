"""Shared artifact action selection helpers.

Used by: artifact action modules when an operation must resolve exactly one
artifact before rendering or mutation.
"""

from __future__ import annotations

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext

from .query import select_artifacts


def single_selected_artifact(context: CommandContext, selectors: dict[str, list[str]], action: str) -> Artifact:
    """Return exactly one selected artifact for mutation or display commands.

    Called by: artifact show/cat/remove/replace helpers that must not act on a
    broad selector set.
    """
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        raise ValueError(f"{action} matched no artifacts")
    if len(artifacts) > 1:
        # Mutation/display commands require an unambiguous artifact. Listing and
        # export-directory actions are the paths that intentionally handle sets.
        raise ValueError(f"{action} matched multiple artifacts; use artifact=<id>")
    return artifacts[0]
