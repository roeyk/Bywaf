"""Shared artifact command constants.

Keeps selector and search vocabulary in one place so the commandlet metadata,
parser, and search implementation cannot drift independently.

Used by:
- runtime.artifact: declare commandlet completion metadata.
- runtime.artifact.selectors and runtime.artifact.query: validate selectors."""

from __future__ import annotations

from collections.abc import Callable

from bywaf.plugin import CommandContext

ARTIFACT_ACTIONS = ("attach", "cat", "export", "import", "list", "remove", "replace", "search", "show", "verify")
"""Valid artifact subcommands used by command metadata and dispatch."""

SEARCH_FLAGS = ("--regexp",)
"""Search-only flags accepted by artifact search selector parsing."""

SEARCH_FIELDS = ("name", "filename", "note", "content")
"""Artifact metadata/body fields that the search command can inspect."""

ArtifactActionHandler = Callable[[CommandContext, list[str]], None]
"""Handler signature used by the artifact action dispatch table."""
