"""Non-interactive CLI subcommand dispatch for the top-level app.

Used by:
- bywaf.app.main(): dispatches parsed argparse subcommands after startup.
- bywaf.app.route_direct_commandlet_argv(): uses the subcommand/global-option
  sets to decide whether a bare token should route through `cmd`.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

from .repl import (
    print_commandlets,
    print_history,
    print_plugin_graph,
    print_triggers,
    run_commandlet_remainder,
    run_remainder,
)
from .runner import Runner

CliSubcommandHandler = Callable[[Runner, argparse.Namespace], int]


def exec_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Run a non-interactive OS shell command.

    Called by: `CLI_SUBCOMMAND_HANDLERS["exec"]` from `bywaf.app.main()`.
    """
    return run_remainder(runner, args.command)


def cmd_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Run a direct non-interactive commandlet invocation.

    Called by: `CLI_SUBCOMMAND_HANDLERS["cmd"]` from `bywaf.app.main()`.
    """
    return run_commandlet_remainder(runner, args.command)


def plugins_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print loaded plugin providers or their dependency graph.

    Called by: `CLI_SUBCOMMAND_HANDLERS["plugins"]` from `bywaf.app.main()`.
    """
    if args.action == "graph":
        print_plugin_graph(runner, json_output=args.json, provider=args.provider, topic=args.topic)
        return 0
    print("\n".join(runner.registry.provider_names()))
    return 0


def cmds_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print commandlets grouped by provider.

    Called by: `CLI_SUBCOMMAND_HANDLERS["cmds"]` from `bywaf.app.main()`.
    """
    print_commandlets(runner, page=args.page)
    return 0


def triggers_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print provider-owned trigger rules.

    Called by: `CLI_SUBCOMMAND_HANDLERS["triggers"]` from `bywaf.app.main()`.
    """
    del args
    print_triggers(runner)
    return 0


def history_cli_subcommand(runner: Runner, args: argparse.Namespace) -> int:
    """Print shell history.

    Called by: `CLI_SUBCOMMAND_HANDLERS["history"]` from `bywaf.app.main()`.
    """
    del runner, args
    print_history()
    return 0


# CLI subcommands are framework entrypoints, not plugin commandlets. main() uses
# this dispatch table after argparse so each startup mode stays separated from
# REPL command dispatch.
CLI_SUBCOMMAND_HANDLERS: dict[str | None, CliSubcommandHandler] = {
    "cmd": cmd_cli_subcommand,
    "cmds": cmds_cli_subcommand,
    "history": history_cli_subcommand,
    "plugins": plugins_cli_subcommand,
    "exec": exec_cli_subcommand,
    "triggers": triggers_cli_subcommand,
}


CLI_SUBCOMMANDS = frozenset(("cmd", "exec", "plugins", "cmds", "triggers", "history", "repl"))

# route_direct_commandlet_argv() consults this set while scanning argv so global
# options with values are preserved before routing a bare commandlet name.
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
