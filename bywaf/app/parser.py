"""Argparse setup and direct commandlet routing for the top-level CLI.

Used by:
- bywaf.app.main(): builds the parser and normalizes argv before parsing.
- tests/app_dispatch/test_cli_parser.py: exercises direct commandlet routing
  and supported top-level CLI options.
"""

from __future__ import annotations

import argparse

from ..repl.resources import DEFAULT_DATABASE
from ..runner import add_runner_arguments
from .dispatch import CLI_SUBCOMMANDS, GLOBAL_OPTIONS_WITH_VALUES


def build_parser() -> argparse.ArgumentParser:
    """Build the non-interactive command-line interface.

    Called by: `bywaf.app.main()` and CLI parser tests.
    """

    parser = argparse.ArgumentParser(prog="bywaf")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE), help="SQLite database path")
    parser.add_argument("--new", action="store_true", help="create a named project before starting")
    parser.add_argument("--setup", action="store_true", help="create user configuration and a default project")
    parser.add_argument("--setup-plugin-signing-keys", action="store_true", help=argparse.SUPPRESS)
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
    plugins_parser = subparsers.add_parser("plugins", help="list loaded plugin providers")
    plugins_parser.add_argument("action", nargs="?", choices=("graph",), help="optional plugin catalog action")
    plugins_parser.add_argument("--provider", help="show graph context for one provider path")
    plugins_parser.add_argument("--topic", help="show graph context for one topic")
    plugins_parser.add_argument("--json", action="store_true", help="emit machine-readable plugin graph data")
    subparsers.add_parser("cmds", help="show commandlets grouped by plugin provider").add_argument("--page", action="store_true")
    subparsers.add_parser("triggers", help="show provider-owned trigger rules")
    subparsers.add_parser("history", help="show command history")
    subparsers.add_parser("repl", help="start interactive shell")
    return parser


def database_argument_is_explicit(argv: list[str]) -> bool:
    """Return True when argv contains an explicit --database option.

    Called by: `bywaf.app.main()` before argparse fills in the default DB path.
    """
    return any(arg == "--database" or arg.startswith("--database=") for arg in argv)


def route_direct_commandlet_argv(argv: list[str]) -> list[str]:
    """Route `bywaf <commandlet> ...` through the hidden commandlet CLI path.

    Called by: `bywaf.app.main()` before argparse parses argv. The scan uses
    `GLOBAL_OPTIONS_WITH_VALUES` and `CLI_SUBCOMMANDS` from `app.dispatch` so
    global options stay attached to their values while bare commandlet names are
    routed through `cmd`.
    """
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
    """Remove a leading `project=name` selector from OS CLI argv.

    Called by: `bywaf.app.main()` before direct commandlet routing.
    """
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
