"""Top-level CLI startup and command dispatch.

Provides the argparse entrypoint, runner construction, database/project setup,
plugin trust policy loading, and top-level command routing.

Used by:
- bywaf.__main__: calls main() for the installed `bywaf` command.
- tests and smoke scripts: import make_runner(), main(), and compatibility
  exports while exercising CLI and REPL workflows."""


from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .cli_trust import load_filesystem_registry, merge_filesystem_registry, plugin_trust_policy_from_args
from .config import Settings
from .db import EventStore, database_appears_encrypted
from .projects import ProjectPaths, create_project, require_project
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
    print_history,
    print_triggers,
    process_framework_requests,
    read_logical_input,
    record_command_history,
    remove_line_continuation,
    render_prompt,
    repl,
    run_commandlet_remainder,
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
from .runner import Runner, add_runner_arguments
from .setup import first_run_notice_needed, print_first_run_notice, run_setup

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


def build_parser() -> argparse.ArgumentParser:
    """Build the non-interactive command-line interface."""

    parser = argparse.ArgumentParser(prog="bywaf")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE), help="SQLite database path")
    parser.add_argument("--new", action="store_true", help="create a named project before starting")
    parser.add_argument("--setup", action="store_true", help="create user configuration and a default project")
    parser.add_argument("--quiet", action="store_true", help="suppress friendly startup notices")
    parser.add_argument("--encrypt", action="store_true", help="open or create the database with SQLCipher encryption")
    parser.add_argument("--encrypted", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--plugin-root", help="directory containing filesystem plugins")
    parser.add_argument("--plugin-config", help="JSON or simple YAML plugin config")
    parser.add_argument("--plugin-catalog", help="signed JSON catalog for filesystem plugin trust")
    parser.add_argument("--plugin-catalog-key", help="trusted public key for --plugin-catalog")
    parser.add_argument("--plugin-manifest-key", help="trusted public key for filesystem plugin manifest signatures")
    parser.add_argument(
        "--force-plugins",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-untrusted-plugins",
        action="store_true",
        help="load plugins despite missing signatures, missing trusted keys, or mismatched trusted keys",
    )
    parser.add_argument(
        "--allow-unsigned-plugins",
        action="store_true",
        help="load filesystem plugins even when plugin signatures are missing",
    )
    parser.add_argument(
        "--allow-unsigned-plugin-manifests",
        action="store_true",
        help="allow development plugin manifests without manifest signatures",
    )
    parser.add_argument(
        "--allow-missing-plugin-keys",
        action="store_true",
        help="allow plugin signature verification to continue when trusted public keys are missing",
    )
    parser.add_argument(
        "--allow-mismatched-plugin-keys",
        action="store_true",
        help="allow plugin signature verification to continue when signer keys do not match trusted keys",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    subparsers = parser.add_subparsers(dest="subcommand")
    add_runner_arguments(subparsers.add_parser("cmd", help=argparse.SUPPRESS))
    add_runner_arguments(subparsers.add_parser("exec", help="run an OS shell command"))
    subparsers.add_parser("plugins", help="list loaded plugin providers")
    subparsers.add_parser("cmds", help="show commandlets grouped by plugin provider").add_argument("--page", action="store_true")
    subparsers.add_parser("triggers", help="show provider-owned trigger rules")
    subparsers.add_parser("history", help="show command history")
    subparsers.add_parser("repl", help="start interactive shell")
    return parser


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
    database = project.database if project is not None else Path(args.database)
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
        handler = CLI_SUBCOMMAND_HANDLERS.get(args.subcommand)
        if handler is None:
            parser.error(f"unknown subcommand: {args.subcommand}")
        return handler(runner, args)
    finally:
        shutdown_runner(runner)


def handle_setup_startup(args: argparse.Namespace) -> int | None:
    """Handle explicit setup or the optional interactive first-run notice."""
    if args.setup:
        run_setup(output=not args.quiet)
        return 0
    if args.subcommand in ("repl", None) and first_run_notice_needed(quiet=args.quiet):
        print_first_run_notice()
    return None


CliSubcommandHandler = Callable[[Runner, argparse.Namespace], int]


def exec_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Run a non-interactive OS shell command."""
    return run_remainder(runner, args.command)


def cmd_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Run a direct non-interactive commandlet invocation."""
    return run_commandlet_remainder(runner, args.command)


def plugins_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print loaded plugin providers."""
    del args
    print("\n".join(runner.registry.provider_names()))
    return 0


def cmds_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print commandlets grouped by provider."""
    print_commandlets(runner, page=args.page)
    return 0


def triggers_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print provider-owned trigger rules."""
    del args
    print_triggers(runner)
    return 0


def history_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print shell history."""
    del runner, args
    print_history()
    return 0


CLI_SUBCOMMAND_HANDLERS: dict[str | None, CliSubcommandHandler] = {
    "cmd": cmd_cli_subcommand,
    "cmds": cmds_cli_subcommand,
    "history": history_cli_subcommand,
    "plugins": plugins_cli_subcommand,
    "exec": exec_cli_subcommand,
    "triggers": triggers_cli_subcommand,
}


CLI_SUBCOMMANDS = frozenset(("cmd", "exec", "plugins", "cmds", "triggers", "history", "repl"))
GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    (
        "--database",
        "--plugin-root",
        "--plugin-config",
        "--plugin-catalog",
        "--plugin-catalog-key",
        "--plugin-manifest-key",
    )
)


def route_direct_commandlet_argv(argv: list[str]) -> list[str]:
    """Route `bywaf <commandlet> ...` through the hidden commandlet CLI path."""
    routed: list[str] = []
    skip_next = False
    for index, token in enumerate(argv):
        if skip_next:
            routed.append(token)
            skip_next = False
            continue
        if token in GLOBAL_OPTIONS_WITH_VALUES:
            routed.append(token)
            skip_next = True
            continue
        if any(token.startswith(f"{option}=") for option in GLOBAL_OPTIONS_WITH_VALUES):
            routed.append(token)
            continue
        if token.startswith("-"):
            routed.append(token)
            continue
        if token in CLI_SUBCOMMANDS:
            return argv
        return [*routed, "cmd", *argv[index:]]
    return argv


def extract_startup_project(argv: list[str]) -> tuple[str | None, list[str]]:
    """Remove a leading `project=name` selector from OS CLI argv."""
    project_name: str | None = None
    cleaned: list[str] = []
    subcommands = {"exec", "plugins", "cmds", "history", "repl"}
    before_subcommand = True
    for token in argv:
        if before_subcommand and token.startswith("project="):
            project_name = token.split("=", 1)[1]
            continue
        cleaned.append(token)
        if token in subcommands:
            before_subcommand = False
    return project_name, cleaned


def startup_project(name: str | None, *, create: bool) -> ProjectPaths | None:
    """Resolve or create a startup project selected from the OS command line."""
    if name is None:
        return None
    return create_project(name) if create else require_project(name)
