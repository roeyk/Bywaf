"""Command-aware completion candidate generation.

Provides the registry/database/spec-driven completion engine that knows how to
complete commandlets, options, resources, variables, and runtime selectors.

Used by:
- bywaf.completion: wraps candidate generation for readline and prompt-toolkit.
- plugin completers: receive runtime context derived from this core."""


from __future__ import annotations

import shlex
from dataclasses import dataclass

from ..db import EventStore
from ..registry import PluginRegistry
from ..command.names import (
    PROJECT_ALIAS_COMMAND,
    PROJECT_COMMAND,
    SET_COMMAND,
    SETG_COMMAND,
)
from .builtins import BuiltinCompletionMixin
from .catalog import CatalogCompletionMixin
from .plugin_args import PluginArgumentCompletionMixin
from .runtime_meta import RuntimeCompletionMetadataMixin
from .tokens import tokens_after_last_pipe


@dataclass(slots=True)
class CoreCompleter(
    PluginArgumentCompletionMixin,
    BuiltinCompletionMixin,
    CatalogCompletionMixin,
    RuntimeCompletionMetadataMixin,
):
    """Command-aware completion engine backed by specs and runtime state.

    This class returns semantic candidates only.  UI adapters in
    `bywaf.completion` decide how to display or insert them for readline and
    prompt-toolkit.
    """

    registry: PluginRegistry
    db: EventStore | None = None
    active_context: str | None = None
    builtins: tuple[str, ...] = (
        "help",
        "?",
        "history",
        "config",
        "pref",
        "info",
        "cmds",
        "exec",
        "plugin",
        "plugins",
        "pload",
        PROJECT_ALIAS_COMMAND,
        "project",
        "prompt",
        "script",
        "run",
        "topics",
        "triggers",
        "use",
        SET_COMMAND,
        SETG_COMMAND,
        "exit",
        "event",
        "events",
        "quit",
        "q",
    )

    def candidates(self, line: str) -> list[str]:
        """Return raw completion candidates for a full input line."""
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        # Completion is stage-local.  For `a | b par<Tab>`, only tokens after
        # the last pipe should influence command/argument completion.
        tokens = tokens_after_last_pipe(tokens)
        prefix = "" if line.endswith(" ") else (tokens[-1] if tokens else "")
        base = self.base_candidates(tokens, prefix, line.endswith(" "))
        if prefix == "--":
            return sorted(candidate for candidate in set(base) if candidate.startswith("--"))
        return [
            candidate
            for candidate in sorted(set(base))
            if candidate.startswith(prefix) and candidate != prefix
        ]

    def base_candidates(self, tokens: list[str], prefix: str, ended_with_space: bool) -> list[str]:
        """Return unfiltered candidates for the current token context."""
        root_candidates = [*self.builtins, *self.registry.names(), *self.registry.commandlet_aliases()]
        if not tokens or (len(tokens) == 1 and not ended_with_space):
            return root_candidates
        command = tokens[0]
        rest = tokens[1:]
        if self.registry.has_commandlet(command):
            return self.plugin_candidates(command, prefix, rest)

        # Built-in shell commands are completed here because they are not
        # commandlets and therefore do not have CommandSpec metadata.
        dispatch = {
            "?": lambda current_prefix: self.help_candidates(current_prefix),
            "config": self.config_candidates,
            "cmds": lambda current_prefix: self.option_candidates(current_prefix, ("--page",)),
            "event": self.event_candidates,
            "events": lambda _prefix: ["--tail", "last="],
            "exec": lambda _prefix: [],
            "exit": lambda _prefix: [],
            "help": lambda current_prefix: self.help_candidates(current_prefix),
            "history": self.history_candidates,
            "info": lambda _prefix: [],
            "plugin": lambda current_prefix: self.plugin_resource_candidates(current_prefix, rest),
            "plugins": lambda _prefix: [],
            "pload": self.pload_candidates,
            "pref": self.pref_candidates,
            "prompt": lambda _prefix: [],
            PROJECT_ALIAS_COMMAND: lambda current_prefix: self.project_candidates(current_prefix, rest),
            PROJECT_COMMAND: lambda current_prefix: self.project_candidates(current_prefix, rest),
            "q": lambda _prefix: [],
            "quit": lambda _prefix: [],
            "run": lambda _prefix: [],
            "topics": lambda _prefix: self.topic_completion_candidates(),
            "triggers": lambda _prefix: [],
            "use": lambda _prefix: ["global", *self.registry.names(), *self.registry.commandlet_aliases()],
            "script": self.script_candidates,
            SET_COMMAND: lambda current_prefix: self.vars_candidates(current_prefix, rest),
            SETG_COMMAND: lambda current_prefix: self.setg_candidates(current_prefix, rest),
        }
        handler = dispatch.get(command)
        return handler(prefix) if handler is not None else root_candidates
