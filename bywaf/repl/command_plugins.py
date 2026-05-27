"""REPL plugin loading and post-load context selection.

Provides `plugin load=...` and the `pload` shortcut, plus the rules for
optionally switching `use` context after loading a filesystem plugin.

Used by:
- bywaf.repl.commands: registers plugin-loading handlers.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..runner import Runner
from .command_vars import set_active_context
from .resources import load_plugin_resource, parse_resource_assignment

if TYPE_CHECKING:
    from .shell import ShellState


def handle_plugin_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load filesystem plugins."""
    del line
    if rest is None:
        print("usage: plugin load=<path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    plugin_value = ""
    catalog_path: str | None = None
    use_target: str | None = None
    for token in tokens:
        # `plugin load=` is the explicit form. path= optionally remaps the local
        # filesystem plugin into a catalog path for development/testing.
        key, value = parse_resource_assignment(token)
        if key == "load":
            plugin_value = value
        elif key == "path":
            catalog_path = value
        elif key == "--use":
            use_target = value or ""
        elif token == "--use":
            use_target = ""
    if not plugin_value:
        print("usage: plugin load=<path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, plugin_value, forced, catalog_path=catalog_path)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def handle_pload_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Short alias for loading filesystem plugins."""
    del line
    if rest is None:
        print("usage: pload <path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    catalog_path: str | None = None
    use_target: str | None = None
    paths: list[str] = []
    for token in tokens:
        # pload keeps the common path short: the sole positional token is the
        # plugin path, while path=/--use/--force retain the same meanings.
        key, value = parse_resource_assignment(token)
        if token == "--force":
            continue
        if token == "--use":
            use_target = ""
            continue
        if key == "--use":
            use_target = value or ""
            continue
        if key == "path":
            catalog_path = value
            continue
        paths.append(token)
    if len(paths) != 1:
        print("usage: pload <path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, paths[0], forced, catalog_path=catalog_path)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def maybe_use_loaded_commandlet(
    runner: Runner,
    state: ShellState,
    commandlets: Sequence[str],
    target: str | None,
) -> None:
    """Optionally switch active context after loading a plugin provider."""
    if target is None:
        # Loading does not implicitly change `use`; print the likely next step
        # while avoiding surprises for providers with multiple commandlets.
        if commandlets:
            print(f"try: use {commandlets[0]}")
        return
    if target:
        set_active_context(runner, state, target)
        return
    if len(commandlets) == 1:
        set_active_context(runner, state, commandlets[0])
        return
    if not commandlets:
        print("loaded plugin exposes no commandlets")
        return
    print("loaded plugin exposes multiple commandlets; choose one:")
    for commandlet in commandlets:
        print(f"  use {commandlet}")
    print("or reload with --use=<commandlet>")
