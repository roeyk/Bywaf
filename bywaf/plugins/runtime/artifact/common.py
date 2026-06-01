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
SEARCH_FLAGS = ("--regexp",)
SEARCH_FIELDS = ("name", "filename", "note", "content")

ArtifactActionHandler = Callable[[CommandContext, list[str]], None]
