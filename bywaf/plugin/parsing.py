"""Small parsing helpers for plugin commandlets."""

from __future__ import annotations


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values.

    Called by: commandlets when passing stored string defaults into argparse
    boolean flags.
    """
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}
