"""Shared argument parsing helpers for bundled plugins.

Provides common conversion and option parsing utilities used by commandlets to
avoid repeating small argparse/string handling patterns.

Used by:
- bundled plugin modules: normalize commandlet arguments.
- plugin tests: exercise option handling through real commandlets."""


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
