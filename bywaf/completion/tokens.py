"""Token-position helpers for completion.

Provides small parsing utilities used by CoreCompleter and runtime metadata
inference to reason about pipelines and positional argument indexes.

Used by:
- completion engine: locate the active argument position.
- tests: keep completion token behavior stable.
"""

from __future__ import annotations


def positional_index(args: list[str], prefix: str) -> int:
    """Return the positional argument index currently being completed."""
    if not args:
        return 0
    # Completion metadata counts only positional arguments. Options, pipeline
    # separators, and background markers should not shift positional indexes.
    positional = [
        arg for arg in args
        if not arg.startswith("-") and arg not in {"|", "&"}
    ]
    if prefix and positional and positional[-1] == prefix:
        return len(positional) - 1
    return len(positional)


def tokens_after_last_pipe(tokens: list[str]) -> list[str]:
    """Return tokens belonging to the command after the last pipeline marker."""
    if "|" not in tokens:
        return tokens
    last_pipe = len(tokens) - 1 - tokens[::-1].index("|")
    return tokens[last_pipe + 1 :]
