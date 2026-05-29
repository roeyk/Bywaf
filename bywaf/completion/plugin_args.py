"""Plugin commandlet argument completion.

Provides option, selector, positional, variable-reference, and custom hook
completion for registered commandlets.

Used by:
- completion.engine: mixes commandlet-aware completion into CoreCompleter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..plugin import CompletionContext
from ..specs import CompletionSpec
from ..utils import complete_path
from .constants import FRAMEWORK_OPTION_COMPLETIONS, option_is_binary
from .resources import complete_at_file_prefix
from .tokens import positional_index
from .variables import variable_reference_candidates

if TYPE_CHECKING:
    from ..db import EventStore
    from ..registry import PluginRegistry


class PluginArgumentCompletionMixin:
    """Completion helpers for commandlet-owned arguments and options."""

    registry: "PluginRegistry"
    db: "EventStore | None"

    if TYPE_CHECKING:
        def complete_by_spec(self, spec: CompletionSpec, prefix: str) -> list[str]: ...

    def plugin_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return candidates owned by a plugin commandlet."""
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        plugin = self.registry.get(name)

        variable_candidates = self.plugin_variable_candidates(name, prefix)
        if variable_candidates:
            return variable_candidates

        if self.in_from_selector_context(args, prefix):
            return self.framework_from_selector_candidates(prefix)

        if "=" in prefix and not prefix.startswith("--"):
            key_value_candidates = self.plugin_key_value_candidates(name, prefix)
            if key_value_candidates:
                return key_value_candidates

        if args and not prefix.startswith("--"):
            previous = args[-2] if prefix and args[-1] == prefix and len(args) >= 2 else args[-1]
            value_candidates = self.plugin_option_value_candidates(name, previous, prefix)
            if value_candidates:
                return value_candidates

        custom_candidates = self.plugin_custom_candidates(name, prefix, args)
        matching_custom_candidates = [candidate for candidate in custom_candidates if candidate.startswith(prefix)]
        if matching_custom_candidates:
            return matching_custom_candidates

        if not prefix.startswith("--"):
            positional_candidates = self.plugin_positional_candidates(name, prefix, args)
            matching_positional_candidates = [candidate for candidate in positional_candidates if candidate.startswith(prefix)]
            if matching_positional_candidates:
                return matching_positional_candidates
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

    def framework_from_selector_candidates(self, prefix: str) -> list[str]:
        """Complete selector values used after `--from`."""
        selectors = (("job=", "job"), ("pipeline=", "pipeline"), ("step=", "step"), ("topic=", "topic"))
        for selector, spec_kind in selectors:
            if prefix.startswith(selector):
                value_prefix = prefix.split("=", 1)[1]
                return [f"{selector}{value}" for value in self.complete_by_spec(CompletionSpec(spec_kind), value_prefix)]
        return [selector for selector, _spec_kind in selectors if selector.startswith(prefix)]

    def in_from_selector_context(self, args: list[str], prefix: str) -> bool:
        """Return whether the current token belongs to framework `--from` selectors."""
        if "--from" not in args:
            return False
        if prefix and not any(selector.startswith(prefix) or prefix.startswith(selector) for selector in ("job=", "pipeline=", "step=", "topic=")):
            return False
        from_index = args.index("--from")
        following = args[from_index + 1 :]
        if prefix and following and following[-1] == prefix:
            following = following[:-1]
        if not following:
            return True
        return all(self.is_from_selector_token(token) for token in following)

    def is_from_selector_token(self, token: str) -> bool:
        """Return whether one token is a complete `--from` selector assignment."""
        key, separator, value = token.partition("=")
        return bool(separator and value and key in {"job", "pipeline", "step", "topic"})

    def plugin_variable_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete variable references in positional or key=value arguments."""
        plugin_name = self.registry.variable_scope(plugin_name)
        key = ""
        value_prefix = prefix
        if "=" in prefix and not prefix.startswith("--"):
            key, value_prefix = prefix.split("=", 1)
        if not value_prefix.startswith("$"):
            return []
        variable_prefix = value_prefix[1:]
        candidates = variable_reference_candidates(self.registry.varstore.names(), plugin_name, variable_prefix)
        if key:
            return [f"{key}={candidate}" for candidate in candidates]
        return candidates

    def plugin_key_value_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete explicit `name=value` arguments for valued commandlet options."""
        variable_scope = self.registry.variable_scope(plugin_name)
        plugin_name = self.registry.resolve_commandlet_name(plugin_name)
        key, value_prefix = prefix.split("=", 1)
        plugin = self.registry.get(plugin_name)
        for option in plugin.spec.options:
            if option.name != key or option_is_binary(option.name):
                continue
            completion_candidates = self.complete_by_spec(option.completion, value_prefix)
            if completion_candidates:
                return [f"{key}={candidate}" for candidate in completion_candidates]
            candidates = [*option.choices]
            stored = self.registry.varstore.get(f"{variable_scope}.{option.name}")
            if stored:
                candidates.append(stored)
            if option.default:
                candidates.append(option.default)
            return [f"{key}={candidate}" for candidate in candidates]
        return []

    def plugin_option_value_candidates(self, plugin_name: str, option_token: str, prefix: str) -> list[str]:
        """Complete a value for a plugin option or framework selector."""
        variable_scope = self.registry.variable_scope(plugin_name)
        plugin_name = self.registry.resolve_commandlet_name(plugin_name)
        if option_token in FRAMEWORK_OPTION_COMPLETIONS:
            return self.complete_by_spec(FRAMEWORK_OPTION_COMPLETIONS[option_token], prefix)
        if not option_token.startswith("--"):
            return []
        option_name = option_token[2:]
        plugin = self.registry.get(plugin_name)
        for option in plugin.spec.options:
            if option.name != option_name:
                continue
            completion_candidates = self.complete_by_spec(option.completion, prefix)
            if completion_candidates:
                return completion_candidates
            candidates = [*option.choices]
            stored = self.registry.varstore.get(f"{variable_scope}.{option.name}")
            if stored:
                candidates.append(stored)
            if option.default:
                candidates.append(option.default)
            return candidates
        return []

    def plugin_custom_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Ask a plugin's optional `complete()` hook for candidates."""
        plugin_name = self.registry.resolve_commandlet_name(plugin_name)
        plugin = self.registry.get(plugin_name)
        completer = getattr(plugin, "complete", None)
        if completer is None:
            return []
        context = CompletionContext(
            db=self.db,
            varstore=self.registry.varstore,
            metadata={"commandlets": tuple(self.registry.names())},
        )
        candidates = completer(context, args, prefix)
        return list(candidates) if candidates else []

    def plugin_positional_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Complete the current positional argument from CommandSpec metadata."""
        plugin_name = self.registry.resolve_commandlet_name(plugin_name)
        plugin = self.registry.get(plugin_name)
        position = positional_index(args, prefix)
        if position >= len(plugin.spec.arguments):
            return []
        return self.complete_by_spec(plugin.spec.arguments[position].completion, prefix)
