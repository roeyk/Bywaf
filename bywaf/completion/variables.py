"""Variable-name completion helpers for REPL built-ins.

Called by: `BuiltinCompletionMixin.vars_candidates()` and
`BuiltinCompletionMixin.setg_candidates()` to keep variable-scope completion
separate from command/resource completion logic.
"""

from __future__ import annotations

from collections.abc import Sequence


def variable_reference_candidates(names: Sequence[str], commandlet: str, prefix: str) -> list[str]:
    """Return `$variable` completions using commandlet and global shorthand."""
    candidates: set[str] = set()
    commandlet_prefix = f"{commandlet}."
    for name in names:
        # Prefer short `$timeout` style references for the active commandlet and
        # globals, but always expose `${full.scope.name}` for unambiguous use.
        if name.startswith(commandlet_prefix):
            candidates.add(f"${name.removeprefix(commandlet_prefix)}")
        if name.startswith("global."):
            candidates.add(f"${name.removeprefix('global.')}")
        candidates.add(f"${{{name}}}")
        if "/" not in name and "." not in name:
            candidates.add(f"${name}")
    full_prefix = f"${prefix}"
    return sorted(candidate for candidate in candidates if candidate.startswith(full_prefix))


def secret_option_candidates(args: list[str]) -> list[str]:
    """Return the secret option candidate when it has not already been used."""
    return [] if "--secret" in args else ["--secret"]


def is_qualified_variable_prefix(prefix: str) -> bool:
    """Return whether a variable prefix names an explicit variable scope."""
    return prefix.startswith("global.") or ("/" in prefix and "." in prefix)


def qualified_variable_candidates(prefix: str, names: list[str], catalog_names: list[str]) -> list[str]:
    """Complete fully-qualified variable names."""
    return [f"{name}=" for name in all_variable_names(names, catalog_names) if name.startswith(prefix)]


def context_var_candidates(active_context: str | None, names: list[str]) -> list[str]:
    """Complete short variable names for the active `use` context."""
    if not active_context:
        return []
    scoped_prefix = f"{active_context}."
    return [f"{name.removeprefix(scoped_prefix)}=" for name in names if name.startswith(scoped_prefix)]


def unscoped_variable_candidates(prefix: str, names: list[str], catalog_names: list[str]) -> list[str]:
    """Complete commandlet scopes and global-style variable names."""
    all_names = all_variable_names(names, catalog_names)
    return [
        *commandlet_scope_candidates(prefix, all_names),
        *[f"{name}=" for name in all_names if "/" not in name and name.startswith(prefix)],
    ]


def commandlet_scope_candidates(prefix: str, names: list[str]) -> list[str]:
    """Complete commandlet variable scopes such as `discovery/hostscanner.`."""
    scopes = sorted({name.rsplit(".", 1)[0] for name in names if "/" in name and "." in name})
    return [f"{scope}." for scope in scopes if f"{scope}.".startswith(prefix)]


def all_variable_names(names: list[str], catalog_names: list[str]) -> list[str]:
    """Return stable unique variable names from runtime and catalog sources."""
    return sorted(set(names).union(catalog_names))
