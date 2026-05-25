"""Variable-reference completion helpers.

Provides `$name` and `${scope.variable}` candidates used by plugin argument
completion.
"""

from __future__ import annotations

from collections.abc import Sequence


def variable_reference_candidates(names: Sequence[str], commandlet: str, prefix: str) -> list[str]:
    """Return `$variable` completions using commandlet and global shorthand."""
    candidates: set[str] = set()
    commandlet_prefix = f"{commandlet}."
    for name in names:
        if name.startswith(commandlet_prefix):
            candidates.add(f"${name.removeprefix(commandlet_prefix)}")
        if name.startswith("global."):
            candidates.add(f"${name.removeprefix('global.')}")
        candidates.add(f"${{{name}}}")
        if "/" not in name and "." not in name:
            candidates.add(f"${name}")
    full_prefix = f"${prefix}"
    return sorted(candidate for candidate in candidates if candidate.startswith(full_prefix))
