"""Plugin commandlet argument completion.

Provides option, selector, positional, variable-reference, and custom hook
completion for registered commandlets.

Used by:
- completion.engine: mixes commandlet-aware completion into CoreCompleter.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ...specs import CompletionSpec
from ..resources import complete_at_file_prefix
from .selectors import (
    framework_from_selector_candidates,
    in_from_selector_context,
    is_from_selector_token,
)
from .values import (
    custom_candidates,
    declared_option_candidates,
    first_candidate_group,
    key_value_candidates,
    option_value_candidates,
    positional_candidates,
    variable_candidates,
)

if TYPE_CHECKING:
    from ...db import EventStore
    from ...plugin import Commandlet
    from ...registry import PluginRegistry


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

        contextual_candidates = self.first_plugin_candidate_group(
            (
                lambda: self.plugin_variable_candidates(name, prefix),
                lambda: self.plugin_from_selector_candidates(args, prefix),
                lambda: self.plugin_key_value_candidates_if_needed(name, prefix),
                lambda: self.plugin_option_value_candidates_if_needed(name, prefix, args),
                lambda: self.prefixed_plugin_custom_candidates(name, prefix, args),
                lambda: self.prefixed_plugin_positional_candidates(name, prefix, args),
            )
        )
        if contextual_candidates:
            return contextual_candidates
        return self.plugin_declared_option_candidates(plugin, prefix)

    def first_plugin_candidate_group(self, providers: tuple[Callable[[], list[str]], ...]) -> list[str]:
        """Return the first non-empty plugin completion candidate group."""
        return first_candidate_group(providers)

    def plugin_from_selector_candidates(self, args: list[str], prefix: str) -> list[str]:
        """Complete framework `--from` selectors when the cursor is in that context."""
        if self.in_from_selector_context(args, prefix):
            return self.framework_from_selector_candidates(prefix)
        return []

    def plugin_key_value_candidates_if_needed(self, name: str, prefix: str) -> list[str]:
        """Complete `name=value` option assignments when the token is assignment-like."""
        if "=" in prefix and not prefix.startswith("--"):
            return self.plugin_key_value_candidates(name, prefix)
        return []

    def plugin_option_value_candidates_if_needed(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Complete a separate option value when the previous token names an option."""
        if not args or prefix.startswith("--"):
            return []
        previous = args[-2] if prefix and args[-1] == prefix and len(args) >= 2 else args[-1]
        return self.plugin_option_value_candidates(name, previous, prefix)

    def prefixed_plugin_custom_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return plugin hook candidates matching the current prefix."""
        return [candidate for candidate in self.plugin_custom_candidates(name, prefix, args) if candidate.startswith(prefix)]

    def prefixed_plugin_positional_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return positional metadata candidates matching the current prefix."""
        if prefix.startswith("--"):
            return []
        return [candidate for candidate in self.plugin_positional_candidates(name, prefix, args) if candidate.startswith(prefix)]

    def plugin_declared_option_candidates(self, plugin: "Commandlet", prefix: str) -> list[str]:
        """Return declared commandlet option candidates for the current prefix."""
        return declared_option_candidates(plugin, prefix)

    def framework_from_selector_candidates(self, prefix: str) -> list[str]:
        """Complete selector values used after `--from`."""
        return framework_from_selector_candidates(self.complete_by_spec, prefix)

    def in_from_selector_context(self, args: list[str], prefix: str) -> bool:
        """Return whether the current token belongs to framework `--from` selectors."""
        return in_from_selector_context(args, prefix)

    def is_from_selector_token(self, token: str) -> bool:
        """Return whether one token is a complete `--from` selector assignment."""
        return is_from_selector_token(token)

    def plugin_variable_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete variable references in positional or key=value arguments."""
        return variable_candidates(self.registry, plugin_name, prefix)

    def plugin_key_value_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete explicit `name=value` arguments for valued commandlet options."""
        return key_value_candidates(self.registry, self.complete_by_spec, plugin_name, prefix)

    def plugin_option_value_candidates(self, plugin_name: str, option_token: str, prefix: str) -> list[str]:
        """Complete a value for a plugin option or framework selector."""
        return option_value_candidates(self.registry, self.complete_by_spec, plugin_name, option_token, prefix)

    def plugin_custom_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Ask a plugin's optional `complete()` hook for candidates."""
        return custom_candidates(self.registry, self.db, plugin_name, prefix, args)

    def plugin_positional_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Complete the current positional argument from CommandSpec metadata."""
        return positional_candidates(self.registry, self.complete_by_spec, plugin_name, prefix, args)
