"""Plugin argument and option value completion helpers.

Used by: `PluginArgumentCompletionMixin`, which supplies registry state and the
core `complete_by_spec()` callback from `CoreCompleter`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..plugin import CompletionContext
from ..specs import CompletionSpec
from ..utils import complete_path
from .constants import FRAMEWORK_OPTION_COMPLETIONS, option_is_binary
from .tokens import positional_index
from .variables import variable_reference_candidates

if TYPE_CHECKING:
    from ..db import EventStore
    from ..plugin import Commandlet
    from ..registry import PluginRegistry

CompleteBySpec = Callable[[CompletionSpec, str], list[str]]


def first_candidate_group(providers: tuple[Callable[[], list[str]], ...]) -> list[str]:
    """Return the first non-empty plugin completion candidate group."""
    for provider in providers:
        candidates = provider()
        if candidates:
            return candidates
    return []


def declared_option_candidates(plugin: "Commandlet", prefix: str) -> list[str]:
    """Return declared commandlet option candidates for the current prefix."""
    # Normal commandlet completion is schema-driven: only declared
    # @option/@argument metadata should create commandlet candidates.
    # Framework replay selectors are still available after an operator
    # explicitly types `--from`, but they are not advertised as plugin
    # options because they do not belong to the commandlet spec.
    binary_flags = [f"--{option.name}" for option in plugin.spec.options if option_is_binary(option.name)]
    valued_options = [f"{option.name}=" for option in plugin.spec.options if not option_is_binary(option.name)]
    if prefix.startswith(".") or "/" in prefix:
        return complete_path(prefix)
    return [*valued_options, *binary_flags]


def variable_candidates(registry: "PluginRegistry", plugin_name: str, prefix: str) -> list[str]:
    """Complete variable references in positional or key=value plugin arguments."""
    plugin_name = registry.variable_scope(plugin_name)
    key = ""
    value_prefix = prefix
    if "=" in prefix and not prefix.startswith("--"):
        key, value_prefix = prefix.split("=", 1)
    if not value_prefix.startswith("$"):
        return []
    variable_prefix = value_prefix[1:]
    candidates = variable_reference_candidates(registry.varstore.names(), plugin_name, variable_prefix)
    if key:
        return [f"{key}={candidate}" for candidate in candidates]
    return candidates


def key_value_candidates(
    registry: "PluginRegistry",
    complete_by_spec: CompleteBySpec,
    plugin_name: str,
    prefix: str,
) -> list[str]:
    """Complete explicit `name=value` assignments for valued commandlet options."""
    variable_scope = registry.variable_scope(plugin_name)
    plugin_name = registry.resolve_commandlet_name(plugin_name)
    key, value_prefix = prefix.split("=", 1)
    plugin = registry.get(plugin_name)
    for option in plugin.spec.options:
        if option.name != key or option_is_binary(option.name):
            continue
        candidates = option_value_choices(registry, complete_by_spec, variable_scope, option, value_prefix)
        return [f"{key}={candidate}" for candidate in candidates]
    return []


def option_value_candidates(
    registry: "PluginRegistry",
    complete_by_spec: CompleteBySpec,
    plugin_name: str,
    option_token: str,
    prefix: str,
) -> list[str]:
    """Complete a value for a plugin option or framework selector."""
    variable_scope = registry.variable_scope(plugin_name)
    plugin_name = registry.resolve_commandlet_name(plugin_name)
    if option_token in FRAMEWORK_OPTION_COMPLETIONS:
        return complete_by_spec(FRAMEWORK_OPTION_COMPLETIONS[option_token], prefix)
    if not option_token.startswith("--"):
        return []
    option_name = option_token[2:]
    plugin = registry.get(plugin_name)
    for option in plugin.spec.options:
        if option.name == option_name:
            return option_value_choices(registry, complete_by_spec, variable_scope, option, prefix)
    return []


def option_value_choices(
    registry: "PluginRegistry",
    complete_by_spec: CompleteBySpec,
    variable_scope: str,
    option,
    prefix: str,
) -> list[str]:
    """Return value candidates from completion specs, choices, stored values, and defaults."""
    completion_candidates = complete_by_spec(option.completion, prefix)
    if completion_candidates:
        return completion_candidates
    candidates = [*option.choices]
    stored = registry.varstore.get(f"{variable_scope}.{option.name}")
    if stored:
        candidates.append(stored)
    if option.default:
        candidates.append(option.default)
    return candidates


def custom_candidates(
    registry: "PluginRegistry",
    db: "EventStore | None",
    plugin_name: str,
    prefix: str,
    args: list[str],
) -> list[str]:
    """Ask a plugin's optional `complete()` hook for candidates."""
    plugin_name = registry.resolve_commandlet_name(plugin_name)
    plugin = registry.get(plugin_name)
    completer = getattr(plugin, "complete", None)
    if completer is None:
        return []
    context = CompletionContext(
        db=db,
        varstore=registry.varstore,
        metadata={"commandlets": tuple(registry.names())},
    )
    candidates = completer(context, args, prefix)
    return list(candidates) if candidates else []


def positional_candidates(
    registry: "PluginRegistry",
    complete_by_spec: CompleteBySpec,
    plugin_name: str,
    prefix: str,
    args: list[str],
) -> list[str]:
    """Complete the current positional argument from CommandSpec metadata."""
    plugin_name = registry.resolve_commandlet_name(plugin_name)
    plugin = registry.get(plugin_name)
    position = positional_index(args, prefix)
    if position >= len(plugin.spec.arguments):
        return []
    return complete_by_spec(plugin.spec.arguments[position].completion, prefix)
