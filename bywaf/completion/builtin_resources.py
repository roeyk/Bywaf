"""Built-in resource and project completion helpers.

Used by: `completion.builtins.BuiltinCompletionMixin` for REPL built-ins that
complete project, plugin-resource, preference, config, history, and script
selectors rather than commandlet `CommandSpec` metadata.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..command.names import PROJECT_ACTIONS, PROJECT_ARCHIVE, PROJECT_EXPORT, PROJECT_NEW, PROJECT_USE
from ..projects import list_projects
from .resources import complete_resource_value, resource_candidates

if TYPE_CHECKING:
    from ..registry import PluginRegistry


class BuiltinResourceCompletionMixin:
    """Completion helpers for resource-oriented REPL built-ins."""

    registry: "PluginRegistry"

    if TYPE_CHECKING:
        def catalog_path_candidates(self, prefix: str) -> list[str]: ...
        def option_candidates(self, prefix: str, options: tuple[str, ...]) -> list[str]: ...

    def plugin_resource_candidates(self, prefix: str, args: list[str]) -> list[str]:
        """Complete plugin resource actions."""
        del args
        if prefix.startswith("load="):
            value = prefix.split("=", 1)[1]
            return [f"load={candidate}" for candidate in complete_resource_value("plugin", value)]
        return resource_candidates(prefix, ("--force", "--use", "load=", "path=", "use="))

    def pload_candidates(self, prefix: str) -> list[str]:
        """Complete short-form plugin load paths."""
        if prefix.startswith("-"):
            return self.option_candidates(prefix, ("--force", "--use", "use="))
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
