"""Shared artifact action selection helpers.

Used by: artifact action modules when an operation must resolve exactly one
artifact before rendering or mutation.
"""

from __future__ import annotations

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext

from .query import select_artifacts


def single_selected_artifact(context: CommandContext, selectors: dict[str, list[str]], action: str) -> Artifact:
    """Return exactly one selected artifact for mutation or display commands."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        raise ValueError(f"{action} matched no artifacts")
    if len(artifacts) > 1:
        raise ValueError(f"{action} matched multiple artifacts; use artifact=<id>")
    return artifacts[0]
