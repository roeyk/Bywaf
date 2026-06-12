"""Small parsing helpers for plugin commandlets.

Used by:
- plugin authors, command contexts, plugin checks, and runner commandlet execution.
"""

from __future__ import annotations


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values.

    Called by: commandlets when passing stored string defaults into argparse
    boolean flags.
    """
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def kv_to_args(args: list[str], keys: set[str]) -> list[str]:
    """Convert selected `key=value` tokens into argparse long options.

    Called by: commandlets that accept Bywaf-style `name=value` options while
    still using argparse internally.
    """
    normalized: list[str] = []
    for arg in args:
        key, separator, value = arg.partition("=")
        if separator and key in keys:
            # Bywaf users type option=value, while argparse commandlets often
            # define --option. Convert only declared keys so positional values
            # containing '=' are left alone.
            normalized.extend([f"--{key}", value])
        else:
            normalized.append(arg)
    return normalized


def reject_option_equals(args: list[str], keys: set[str], *, usage: str) -> None:
    """Reject value-carrying `--option=value` forms for Bywaf-owned options."""
    flags = {f"--{key}" for key in keys}
    for arg in args:
        key, separator, _value = arg.partition("=")
        if separator and key in flags:
            raise ValueError(usage)
