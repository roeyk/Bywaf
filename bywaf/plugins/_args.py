"""Small argument helpers shared by bundled plugins."""

from __future__ import annotations


def key_value_to_long_options(args: list[str], keys: set[str]) -> list[str]:
    """Convert selected `key=value` tokens into argparse long options."""
    normalized: list[str] = []
    for arg in args:
        key, separator, value = arg.partition("=")
        if separator and key in keys:
            normalized.extend([f"--{key}", value])
        else:
            normalized.append(arg)
    return normalized
