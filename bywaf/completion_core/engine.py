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
from ..plugin import CompletionContext
from ..projects import list_projects
from ..registry import PluginRegistry
from ..command_names import (
    PROJECT_ACTIONS,
    PROJECT_ALIAS_COMMAND,
    PROJECT_ARCHIVE,
    PROJECT_COMMAND,
    PROJECT_EXPORT,
    PROJECT_NEW,
    PROJECT_USE,
    SET_COMMAND,
    SETG_COMMAND,
)
from ..specs import CompletionSpec
from ..utils import complete_path
from .constants import FRAMEWORK_OPTION_COMPLETIONS, option_is_binary
from .providers import bundle_candidates, key_candidates
from .resources import complete_at_file_prefix, complete_resource_value, resource_candidates
from .runtime import runtime_completion_target
from .tokens import positional_index, tokens_after_last_pipe
from .variables import variable_reference_candidates


@dataclass(slots=True)
class CoreCompleter:
    """Command-aware completion engine backed by specs and runtime state."""

    registry: PluginRegistry
    db: EventStore | None = None
    active_context: str | None = None
    builtins: tuple[str, ...] = (
        "help",
        "?",
        "history",
        "config",
        "info",
        "jobs",
        "pipelines",
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
        "step",
        "steps",
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
            "jobs": lambda current_prefix: self.option_candidates(current_prefix, ("--all", "--page")),
            "pipelines": lambda current_prefix: self.option_candidates(current_prefix, ("--page",)),
            "plugin": lambda current_prefix: self.plugin_resource_candidates(current_prefix, rest),
            "plugins": lambda _prefix: [],
            "pload": self.pload_candidates,
            "prompt": lambda _prefix: [],
            PROJECT_ALIAS_COMMAND: lambda current_prefix: self.project_candidates(current_prefix, rest),
            PROJECT_COMMAND: lambda current_prefix: self.project_candidates(current_prefix, rest),
            "q": lambda _prefix: [],
            "quit": lambda _prefix: [],
            "run": lambda _prefix: [],
            "step": lambda current_prefix: self.complete_by_spec(CompletionSpec("run"), current_prefix),
            "steps": lambda current_prefix: self.option_candidates(current_prefix, ("--all",)),
            "topics": lambda _prefix: self.topic_completion_candidates(),
            "triggers": lambda _prefix: [],
            "use": lambda _prefix: ["global", *self.registry.names(), *self.registry.commandlet_aliases()],
            "script": self.script_candidates,
            SET_COMMAND: lambda current_prefix: self.vars_candidates(current_prefix, rest),
            SETG_COMMAND: lambda current_prefix: self.setg_candidates(current_prefix, rest),
        }
        handler = dispatch.get(command)
        return handler(prefix) if handler is not None else root_candidates

    def plugin_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return candidates owned by a plugin commandlet.

        Completion is intentionally layered: custom plugin hook, option values,
        positional argument specs, then generic framework/plugin metadata. This
        keeps command-specific behavior out of the core completer.
        """
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        plugin = self.registry.get(name)
        variable_candidates = self.plugin_variable_candidates(name, prefix)
        if variable_candidates:
            return variable_candidates
        if "=" in prefix and not prefix.startswith("--"):
            key_value_candidates = self.plugin_key_value_candidates(name, prefix)
            if key_value_candidates:
                return key_value_candidates
        if args and not prefix.startswith("--"):
            previous = args[-2] if prefix and args[-1] == prefix and len(args) >= 2 else args[-1]
            value_candidates = self.plugin_option_value_candidates(name, previous, prefix)
            if value_candidates:
                return value_candidates
        if not prefix.startswith("--"):
            custom_candidates = self.plugin_custom_candidates(name, prefix, args)
            matching_custom_candidates = [candidate for candidate in custom_candidates if candidate.startswith(prefix)]
            if matching_custom_candidates:
                return matching_custom_candidates
        if not prefix.startswith("--"):
            positional_candidates = self.plugin_positional_candidates(name, prefix, args)
            matching_positional_candidates = [candidate for candidate in positional_candidates if candidate.startswith(prefix)]
            if matching_positional_candidates:
                return matching_positional_candidates
        binary_flags = [f"--{option.name}" for option in plugin.spec.options if option_is_binary(option.name)]
        valued_options = [f"{option.name}=" for option in plugin.spec.options if not option_is_binary(option.name)]
        options = ["-h", "--help", *binary_flags]
        options.extend(("--from-run", "--from-pipeline", "--from-topic"))
        if prefix.startswith(".") or "/" in prefix:
            return complete_path(prefix)
        return [*valued_options, *options, *plugin.spec.consumes, *plugin.spec.emits]

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

    def topic_candidates(self) -> list[str]:
        """Return topic-like candidates from plugin specs and the active DB."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        job_candidates = [f"job={row['id']}" for row in self.db.jobs()] if self.db else []
        return [*plugin_topics, *db_topics, *job_candidates]

    def event_candidates(self, prefix: str) -> list[str]:
        """Complete `event` selectors and selector values."""
        if prefix.isdigit():
            if not self.db:
                return []
            return [str(event.id) for event in self.db.recent_events(50) if str(event.id).startswith(prefix)]
        selectors = ("job=", "run=", "pipeline=", "serial=", "topic=")
        for selector in selectors:
            if prefix.startswith(selector):
                value_prefix = prefix.split("=", 1)[1]
                kind = selector[:-1]
                return [f"{selector}{value}" for value in self.complete_by_spec(CompletionSpec(kind), value_prefix)]
        if prefix:
            selector_matches = [selector for selector in selectors if selector.startswith(prefix)]
            if selector_matches:
                return selector_matches
        return [*self.topic_candidates(), *selectors]

    def run_candidates(self) -> list[str]:
        """Complete command run IDs from the active database."""
        if not self.db:
            return []
        return [row["command_run_id"] for row in self.db.runs()]

    def pipeline_candidates(self) -> list[str]:
        """Complete pipeline IDs from the active database."""
        if not self.db:
            return []
        return sorted({row["pipeline_id"] for row in self.db.runs() if row["pipeline_id"]})

    def run_alias_candidates(self) -> list[str]:
        """Complete user-facing run IDs."""
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
        dispatch = {
            "path": lambda: complete_path(prefix or "."),
            "file": lambda: complete_path(prefix or "."),
            "directory": lambda: complete_path(prefix or "."),
            "choice": lambda: list(spec.values),
            "topic": self.topic_completion_candidates,
            "run": self.run_alias_candidates,
            "pipeline": self.pipeline_alias_candidates,
            "job": self.job_candidates,
            "serial": self.serial_candidates,
            "bundle": lambda: bundle_candidates(self.db),
            "key.any": key_candidates,
            "key.signing": lambda: key_candidates(signing=True),
            "key.verify": lambda: key_candidates(verify=True),
            "plugin": self.registry.names,
        }
        handler = dispatch.get(spec.kind)
        return handler() if handler is not None else []

    def topic_completion_candidates(self) -> list[str]:
        """Complete topic names without selector/job decorations."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        return [*plugin_topics, *db_topics]

    def plugin_resource_candidates(self, prefix: str, args: list[str]) -> list[str]:
        """Complete plugin resource actions."""
        del args
        if prefix.startswith("load="):
            value = prefix.split("=", 1)[1]
            return [f"load={candidate}" for candidate in complete_resource_value("plugin", value)]
        return resource_candidates(prefix, ("--force", "--use", "--use=", "load="))

    def pload_candidates(self, prefix: str) -> list[str]:
        """Complete short-form plugin load paths."""
        if prefix.startswith("-"):
            return self.option_candidates(prefix, ("--force", "--use", "--use="))
        return complete_resource_value("plugin", prefix)

    def config_candidates(self, prefix: str) -> list[str]:
        """Complete config subcommands and selectors."""
        return resource_candidates(prefix, ("load", "save", "file=", "--encrypt"))

    def history_candidates(self, prefix: str) -> list[str]:
        """Complete history selectors and resource actions."""
        return resource_candidates(prefix, ("since=", "until=", "load", "save", "file=", "--encrypt"))

    def script_candidates(self, prefix: str) -> list[str]:
        """Complete script load/save selectors."""
        return resource_candidates(prefix, ("load", "save", "file=", "--encrypt"))

    def project_candidates(self, prefix: str, args: list[str]) -> list[str]:
        """Complete REPL project subcommands and selectors."""
        actions = PROJECT_ACTIONS
        if not args or (len(args) == 1 and args[0] == prefix):
            return list(actions)
        action = args[0]
        if action == PROJECT_NEW:
            return self.project_new_candidates(prefix)
        if action == PROJECT_USE:
            return self.project_use_candidates(prefix)
        if action in {PROJECT_ARCHIVE, PROJECT_EXPORT}:
            return resource_candidates(prefix, ("file=", "--encrypt"))
        return []

    def project_new_candidates(self, prefix: str) -> list[str]:
        """Complete `project new` selectors."""
        candidates = ("name=", "--encrypt")
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def project_use_candidates(self, prefix: str) -> list[str]:
        """Complete `project use` selectors and known project names."""
        if prefix.startswith("name="):
            name_prefix = prefix.split("=", 1)[1]
            return [f"name={project.name}" for project in list_projects() if project.name.startswith(name_prefix)]
        candidates = ("name=", "--force")
        if prefix and not prefix.startswith("-"):
            candidates = (*candidates, *[project.name for project in list_projects()])
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def vars_candidates(self, prefix: str, args: list[str] | None = None) -> list[str]:
        """Complete variables, preferring the active `use` context."""
        args = args or []
        secret_already_present = any(arg == "--secret" or arg.startswith("--secret=") for arg in args)
        if prefix.startswith("-"):
            return [] if secret_already_present else ["--secret"]
        names = list(self.registry.varstore.names())
        secret_candidates = [] if secret_already_present else ["--secret"]
        if prefix.startswith("global.") or ("/" in prefix and "." in prefix):
            return [f"{name}=" for name in names if name.startswith(prefix)]
        if self.active_context:
            scoped_prefix = f"{self.active_context}."
            short_names = [
                f"{name.removeprefix(scoped_prefix)}="
                for name in names
                if name.startswith(scoped_prefix)
            ]
            if short_names:
                return [*secret_candidates, *short_names]
        commandlet_scopes = sorted({name.rsplit(".", 1)[0] for name in names if "/" in name and "." in name})
        return [
            *secret_candidates,
            *[f"{scope}." for scope in commandlet_scopes if f"{scope}.".startswith(prefix)],
            *[f"{name}=" for name in names if "/" not in name and name.startswith(prefix)],
        ]

    def setg_candidates(self, prefix: str, args: list[str] | None = None) -> list[str]:
        """Complete global variables for `setg`."""
        args = args or []
        secret_already_present = any(arg == "--secret" or arg.startswith("--secret=") for arg in args)
        if prefix.startswith("-"):
            return [] if secret_already_present else ["--secret"]
        names = [name.removeprefix("global.") for name in self.registry.varstore.names() if name.startswith("global.")]
        return [f"{name}=" for name in names if name.startswith(prefix)]

    def completion_meta(self, candidate: str, line: str, prefix: str) -> str:
        """Return prompt-toolkit metadata for runtime entity completions."""
        if self.db is None:
            return ""
        kind, value = runtime_completion_target(candidate, line, prefix)
        if kind is None:
            return ""
        dispatch = {
            "job": self.job_completion_meta,
            "pipeline": self.pipeline_completion_meta,
            "run": self.run_completion_meta,
        }
        handler = dispatch.get(kind)
        return handler(value) if handler is not None else ""

    def job_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one job completion."""
        if self.db is None:
            return ""
        try:
            row = self.db.job(int(value))
        except ValueError:
            return ""
        if row is None:
            return ""
        artifacts = self.db.artifact_counts_by_job().get(str(row["id"]), 0)
        return f"serial={row['serial']} status={row['status']} artifacts={artifacts} command={row['command_line']}"

    def run_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one run completion."""
        if self.db is None:
            return ""
        serial = self.db.resolve_run_serial(value)
        artifacts = self.db.artifact_counts_by_run().get(serial, 0)
        for row in self.db.runs(active_only=False):
            if row["command_run_id"] == serial:
                return f"serial={serial} source={row['source']} artifacts={artifacts} events={row['events']}"
        return ""

    def pipeline_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one pipeline completion."""
        if self.db is None:
            return ""
        serial = self.db.resolve_pipeline_serial(value)
        artifacts = self.db.artifact_counts_by_pipeline().get(serial, 0)
        for row in self.db.pipelines(active_only=False):
            if row["pipeline_id"] == serial:
                return f"serial={serial} artifacts={artifacts} runs={row['runs']} events={row['events']}"
        return ""
