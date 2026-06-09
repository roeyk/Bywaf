"""Top-level CLI startup and command dispatch.

Provides the argparse entrypoint, runner construction, database/project setup,
plugin trust policy loading, and top-level command routing.

Used by:
- bywaf.__main__: calls main() for the installed `bywaf` command.
- tests and smoke scripts: import make_runner(), main(), and compatibility
  exports while exercising CLI and REPL workflows."""


from __future__ import annotations

import sys
from pathlib import Path

from . import __version__
from .app_dispatch import CLI_SUBCOMMAND_HANDLERS
from .app_parser import build_parser, database_argument_is_explicit, extract_startup_project, route_direct_commandlet_argv
from .app_startup import handle_setup_startup, startup_database_path, startup_project
from .cli_trust import load_filesystem_registry, merge_filesystem_registry, plugin_trust_policy_from_args
from .config import Settings
from .db import EventStore, database_appears_encrypted
from .projects import ProjectPaths
from .registry import PluginRegistry, PluginTrustError, PluginTrustPolicy
from .repl import (
    ShellState,
    command_from_remainder,
    confirm_repl_exit,
    dispatch_repl_line,
    format_event,
    format_history_entry_for_display,
    friendly_error,
    line_has_continuation,
    new_shell_state,
    print_commandlets,
    print_events,
    print_plugin_graph,
    print_history,
    print_triggers,
    process_framework_requests,
    read_logical_input,
    record_command_history,
    remove_line_continuation,
    render_prompt,
    repl,
    run_remainder,
    set_prompt_pattern,
    shutdown_runner,
    split_command_sequence,
)
from .repl.resources import (
    DEFAULT_DATABASE,
    apply_config,
    hydrate_persistent_secrets,
    load_history,
    parse_load_spec,
    parse_save_spec,
    prompt_database_passphrase,
    resolve_resource_path,
    save_history,
)
from .repl.scripts import run_script, script_commands, strip_inline_comment
from .runner import Runner

# Compatibility export list for code that imports helpers from `bywaf.app`.
# The implementation has been split across REPL/resource/runner modules, but
# tests, scripts, and older integrations still use this module as the stable
# top-level CLI facade.
__all__ = [
    "DEFAULT_DATABASE",
    "ShellState",
    "build_parser",
    "command_from_remainder",
    "confirm_repl_exit",
    "dispatch_repl_line",
    "format_event",
    "format_history_entry_for_display",
    "friendly_error",
    "line_has_continuation",
    "load_history",
    "main",
    "make_runner",
    "new_shell_state",
    "parse_load_spec",
    "parse_save_spec",
    "print_commandlets",
    "print_events",
    "print_plugin_graph",
    "print_history",
    "print_triggers",
    "process_framework_requests",
    "read_logical_input",
    "record_command_history",
    "remove_line_continuation",
    "render_prompt",
    "repl",
    "resolve_resource_path",
    "run_remainder",
    "run_script",
    "save_history",
    "script_commands",
    "set_prompt_pattern",
    "shutdown_runner",
    "split_command_sequence",
    "strip_inline_comment",
]

def make_runner(
    database: str | Path,
    *,
    plugin_root: str | Path | None = None,
    plugin_config: str | Path | None = None,
    plugin_catalog: str | Path | None = None,
    plugin_catalog_key: str | Path | None = None,
    plugin_manifest_key: str | Path | None = None,
    forced_plugins: bool = False,
    plugin_trust_policy: PluginTrustPolicy | None = None,
    encrypted: bool = False,
    passphrase: str | None = None,
    project: ProjectPaths | None = None,
) -> Runner:
    """Create a runner with stock plugins plus optional filesystem plugins."""

    database_path = Path(database)
    db_passphrase = passphrase
    if db_passphrase is None and (encrypted or database_appears_encrypted(database_path)):
        db_passphrase = prompt_database_passphrase(database_path, creating=encrypted)
    registry = PluginRegistry.discover()
    db = EventStore(database_path, passphrase=db_passphrase)
    db.mark_stale_jobs()
    if plugin_root and plugin_config:
        filesystem = load_filesystem_registry(
            db,
            Path(plugin_root),
            Path(plugin_config),
            plugin_catalog=Path(plugin_catalog) if plugin_catalog else None,
            plugin_catalog_key=Path(plugin_catalog_key) if plugin_catalog_key else None,
            plugin_manifest_key=Path(plugin_manifest_key) if plugin_manifest_key else None,
            forced_plugins=forced_plugins,
            plugin_trust_policy=plugin_trust_policy,
            varstore=registry.varstore,
        )
        merge_filesystem_registry(registry, filesystem)
    hydrate_persistent_secrets(db, registry)
    return Runner(db, registry, project=project)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by `python -m bywaf` and the console script."""
    project_name, parsed_argv = extract_startup_project(sys.argv[1:] if argv is None else argv)
    parsed_argv = route_direct_commandlet_argv(parsed_argv)
    explicit_database = database_argument_is_explicit(parsed_argv)
    parser = build_parser()
    args = parser.parse_args(parsed_argv)
    if args.version:
        print(__version__)
        return 0
    setup_result = handle_setup_startup(args)
    if setup_result is not None:
        return setup_result
    try:
        project = startup_project(project_name, create=args.new)
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}")
        return 1
    if args.new and project is None:
        print("error: --new requires project=<name>")
        return 1
    database = startup_database_path(project, args.database, explicit_database=explicit_database)
    settings = Settings(database=database)
    try:
        runner = make_runner(
            settings.database,
            plugin_root=args.plugin_root,
            plugin_config=args.plugin_config,
            plugin_catalog=args.plugin_catalog,
            plugin_catalog_key=args.plugin_catalog_key,
            plugin_manifest_key=args.plugin_manifest_key,
            forced_plugins=args.force_plugins,
            plugin_trust_policy=plugin_trust_policy_from_args(args),
            encrypted=args.encrypt or args.encrypted,
            project=project,
        )
    except PluginTrustError as exc:
        print(str(exc))
        return 1
    if project is not None and project.config.exists():
        apply_config(runner, project.config)
    if args.subcommand in ("repl", None):
        repl(runner)
        return 0
    try:
        # This lookup uses the CLI_SUBCOMMAND_HANDLERS dispatch table from
        # app_dispatch.py in place of an if/elif ladder over argparse
        # subcommands.
        handler = CLI_SUBCOMMAND_HANDLERS.get(args.subcommand)
        if handler is None:
            parser.error(f"unknown subcommand: {args.subcommand}")
        return handler(runner, args)
    finally:
        shutdown_runner(runner)
