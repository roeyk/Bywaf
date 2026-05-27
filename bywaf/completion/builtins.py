"""Built-in REPL command completion helpers.

Provides candidate generation for shell-owned commands that do not have
CommandSpec metadata.

Used by:
- completion.engine: mixes built-in command completion into CoreCompleter.
"""

from __future__ import annotations

from ..command.names import (
    PROJECT_ACTIONS,
    PROJECT_ARCHIVE,
    PROJECT_EXPORT,
    PROJECT_NEW,
    PROJECT_USE,
)
from ..projects import list_projects
from ..specs import CompletionSpec
from ..utils import complete_path
from .providers import bundle_candidates, key_candidates
from .resources import complete_at_file_prefix, complete_resource_value, resource_candidates


class BuiltinCompletionMixin:
    """Completion helpers for REPL built-ins and runtime selectors."""

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
        selectors = ("job=", "step=", "pipeline=", "serial=", "topic=")
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
        return resource_candidates(prefix, ("--force", "--use", "--use=", "load=", "path="))

    def pload_candidates(self, prefix: str) -> list[str]:
        """Complete short-form plugin load paths."""
        if prefix.startswith("-"):
            return self.option_candidates(prefix, ("--force", "--use", "--use="))
        if prefix.startswith("path="):
            return [f"path={candidate}" for candidate in self.catalog_path_candidates(prefix.split("=", 1)[1])]
        return complete_resource_value("plugin", prefix)

    def config_candidates(self, prefix: str) -> list[str]:
        """Complete config subcommands and selectors."""
        from ..repl.themes import theme_names

        if prefix.startswith("name="):
            value = prefix.split("=", 1)[1]
            return [f"name={name}" for name in theme_names() if name.startswith(value)]
        return resource_candidates(prefix, ("load", "save", "theme", "file=", "name=", "--encrypt"))

    def pref_candidates(self, prefix: str) -> list[str]:
        """Complete preference actions and common preference keys."""
        from ..repl.themes import theme_names

        common = (
            "list",
            "load",
            "save",
            "set",
            "unset",
            "prompt",
            "file=",
            "theme=",
            "prompt.pattern=",
            "display.expansion=",
            "completion.select-key=",
            "history.timestamp-format=",
            "identity.email=",
            "identity.fullname=",
            "identity.username=",
            "mail.smtp.host=",
            "mail.smtp.port=",
        )
        if prefix.startswith("theme="):
            value = prefix.split("=", 1)[1]
            return [f"theme={name}" for name in theme_names() if name.startswith(value)]
        return resource_candidates(prefix, common)

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
        catalog_names = self.catalog_variable_names()
        secret_candidates = [] if secret_already_present else ["--secret"]
        if prefix.startswith("global.") or ("/" in prefix and "." in prefix):
            return [f"{name}=" for name in sorted(set(names).union(catalog_names)) if name.startswith(prefix)]
        if self.active_context:
            scoped_prefix = f"{self.active_context}."
            short_names = [f"{name.removeprefix(scoped_prefix)}=" for name in names if name.startswith(scoped_prefix)]
            if short_names:
                return [*secret_candidates, *short_names]
        all_names = sorted(set(names).union(catalog_names))
        commandlet_scopes = sorted({name.rsplit(".", 1)[0] for name in all_names if "/" in name and "." in name})
        return [
            *secret_candidates,
            *[f"{scope}." for scope in commandlet_scopes if f"{scope}.".startswith(prefix)],
            *[f"{name}=" for name in all_names if "/" not in name and name.startswith(prefix)],
        ]

    def setg_candidates(self, prefix: str, args: list[str] | None = None) -> list[str]:
        """Complete global variables for `setg`."""
        args = args or []
        secret_already_present = any(arg == "--secret" or arg.startswith("--secret=") for arg in args)
        if prefix.startswith("-"):
            return [] if secret_already_present else ["--secret"]
        names = [name.removeprefix("global.") for name in self.registry.varstore.names() if name.startswith("global.")]
        return [f"{name}=" for name in names if name.startswith(prefix)]
