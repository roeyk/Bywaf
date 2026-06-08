"""Built-in REPL command completion helpers.

Provides candidate generation for shell-owned commands that do not have
CommandSpec metadata.

Used by:
- completion.engine: mixes built-in command completion into CoreCompleter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..specs import CompletionSpec
from ..utils import complete_path
from .builtin_resources import BuiltinResourceCompletionMixin
from .event_selectors import event_candidates, event_selector_value_candidates
from .providers import bundle_candidates, key_candidates
from .resources import complete_at_file_prefix
from .variables import (
    active_context_variable_candidates,
    is_qualified_variable_prefix,
    qualified_variable_candidates,
    secret_option_candidates,
    unscoped_variable_candidates,
)

if TYPE_CHECKING:
    from ..db import EventStore
    from ..registry import PluginRegistry


class BuiltinCompletionMixin(BuiltinResourceCompletionMixin):
    """Completion helpers for REPL built-ins and runtime selectors."""

    registry: "PluginRegistry"
    db: "EventStore | None"
    active_context: str | None
    builtins: tuple[str, ...]

    if TYPE_CHECKING:
        def catalog_path_candidates(self, prefix: str) -> list[str]: ...
        def catalog_variable_names(self) -> list[str]: ...

    def topic_candidates(self) -> list[str]:
        """Return topic-like candidates from plugin specs and the active DB."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        job_candidates = [f"job={row['id']}" for row in self.db.jobs()] if self.db else []
        return [*plugin_topics, *db_topics, *job_candidates]

    def event_candidates(self, prefix: str) -> list[str]:
        """Complete `event` selectors and selector values."""
        return event_candidates(self, prefix)

    def event_selector_value_candidates(self, prefix: str) -> list[str] | None:
        """Complete selector values after `event <selector>=`."""
        return event_selector_value_candidates(self, prefix)

    def run_candidates(self) -> list[str]:
        """Complete pipeline step IDs from the active database."""
        if not self.db:
            return []
        return [row["command_run_id"] for row in self.db.runs()]

    def pipeline_candidates(self) -> list[str]:
        """Complete pipeline IDs from the active database."""
        if not self.db:
            return []
        return sorted({row["pipeline_id"] for row in self.db.runs() if row["pipeline_id"]})

    def run_alias_candidates(self) -> list[str]:
        """Complete user-facing step IDs."""
        if not self.db:
            return []
        return list(self.db.run_aliases().values())

    def pipeline_alias_candidates(self) -> list[str]:
        """Complete user-facing pipeline IDs."""
        if not self.db:
            return []
        return list(self.db.pipeline_aliases().values())

    def serial_candidates(self) -> list[str]:
        """Complete durable serial values."""
        if not self.db:
            return []
        return self.db.serials()

    def job_candidates(self) -> list[str]:
        """Complete job IDs from the active database."""
        if not self.db:
            return []
        return [str(row["id"]) for row in self.db.jobs()]

    def pipeline_expression_candidates(self, prefix: str) -> list[str]:
        """Complete commandlet names for commandlet pipeline expressions."""
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        if prefix.startswith(".") or "/" in prefix:
            return complete_path(prefix)
        return self.registry.names()

    def help_candidates(self, prefix: str) -> list[str]:
        """Complete visible commands and commandlets for `help`."""
        del prefix
        return [*self.builtins, *self.registry.names()]

    def option_candidates(self, prefix: str, options: tuple[str, ...]) -> list[str]:
        """Complete a small fixed option set for built-in commands."""
        return [option for option in options if option.startswith(prefix)]

    def complete_by_spec(self, spec: CompletionSpec, prefix: str) -> list[str]:
        """Resolve a CompletionSpec into concrete candidates."""
        # CompletionSpec kinds are a public plugin-authoring contract.
        # complete_by_spec() uses this dispatch table to keep each kind's provider
        # explicit instead of burying plugin-visible behavior in branches.
        dispatch = {
            "path": lambda: complete_path(prefix or "."),
            "file": lambda: complete_path(prefix or "."),
            "directory": lambda: complete_path(prefix or "."),
            "choice": lambda: list(spec.values),
            "topic": self.topic_completion_candidates,
            "step": self.run_alias_candidates,
            "pipeline": self.pipeline_alias_candidates,
            "job": self.job_candidates,
            "serial": self.serial_candidates,
            "bundle": lambda: bundle_candidates(self.db),
            "key.any": key_candidates,
            "key.signing": lambda: key_candidates(signing=True),
            "key.verify": lambda: key_candidates(verify=True),
            "plugin": self.registry.names,
        }
        # This lookup uses the local CompletionSpec dispatch table above in
        # place of an if/elif ladder over completion kinds.
        handler = dispatch.get(spec.kind)
        return handler() if handler is not None else []

    def topic_completion_candidates(self) -> list[str]:
        """Complete topic names without selector/job decorations."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        return [*plugin_topics, *db_topics]

    def vars_candidates(self, prefix: str, args: list[str] | None = None) -> list[str]:
        """Complete variables, preferring the active `use` context."""
        args = args or []
        secret_candidates = secret_option_candidates(args)
        if prefix.startswith("-"):
            return secret_candidates
        names = list(self.registry.varstore.names())
        catalog_names = self.catalog_variable_names()
        if is_qualified_variable_prefix(prefix):
            return qualified_variable_candidates(prefix, names, catalog_names)
        active_candidates = active_context_variable_candidates(self.active_context, names)
        if active_candidates:
            return [*secret_candidates, *active_candidates]
        return [*secret_candidates, *unscoped_variable_candidates(prefix, names, catalog_names)]

    def setg_candidates(self, prefix: str, args: list[str] | None = None) -> list[str]:
        """Complete global variables for `setg`."""
        args = args or []
        secret_candidates = secret_option_candidates(args)
        if prefix.startswith("-"):
            return secret_candidates
        names = [name.removeprefix("global.") for name in self.registry.varstore.names() if name.startswith("global.")]
        return [f"{name}=" for name in names if name.startswith(prefix)]
