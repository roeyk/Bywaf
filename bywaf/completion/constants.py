"""Shared completion constants.

Provides framework option completion metadata used by the core completion
engine and binary-option classification exposed through the package facade.

Used by:
- completion engine: recognize built-in option and selector completions.
- compatibility facade: export shared constants to older callers.
"""

from __future__ import annotations

from ..specs import CompletionSpec

FRAMEWORK_OPTION_COMPLETIONS = {
    # These options are framework selectors parsed outside commandlet-specific
    # argparse, so completion metadata lives with the completion engine.
    "--from-step": CompletionSpec("step"),
    "--from-pipeline": CompletionSpec("pipeline"),
    "--from-topic": CompletionSpec("topic"),
}
# Binary options complete as bare flags instead of expecting a following value.
BINARY_OPTION_NAMES = {"listen", "silent"}


def option_is_binary(option_name: str) -> bool:
    """Return whether an option should complete as a binary `--flag`."""
    return option_name in BINARY_OPTION_NAMES
