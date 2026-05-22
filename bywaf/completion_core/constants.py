"""Shared completion constants.

Provides framework option completion metadata used by the core completion
engine and binary-option classification exposed through the package facade.
"""

from __future__ import annotations

from ..specs import CompletionSpec

FRAMEWORK_OPTION_COMPLETIONS = {
    "--from-run": CompletionSpec("run"),
    "--from-pipeline": CompletionSpec("pipeline"),
    "--from-topic": CompletionSpec("topic"),
}
BINARY_OPTION_NAMES = {"listen", "silent"}


def option_is_binary(option_name: str) -> bool:
    """Return whether an option should complete as a binary `--flag`."""
    return option_name in BINARY_OPTION_NAMES
