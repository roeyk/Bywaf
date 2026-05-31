"""REPL plugin loading and post-load context selection.

Provides `plugin load=...` and the `pload` shortcut, plus the rules for
optionally switching `use` context after loading a filesystem plugin.

Used by:
- bywaf.repl.commands: registers plugin-loading handlers.
"""

from __future__ import annotations

import shlex
import shutil
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ...runner import Runner
from ...varstore import provider_scope_for
from ..resources import load_plugin_resource, parse_resource_assignment
from .vars import set_active_context

if TYPE_CHECKING:
    from ..state import ShellState


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
    print_loaded_plugin_vars(runner, commandlets)
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
    print_loaded_plugin_vars(runner, commandlets)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def print_loaded_plugin_vars(runner: Runner, commandlets: Sequence[str]) -> None:
    """Print compact assignable variable names exposed by loaded commandlets."""
    stubs = loaded_plugin_var_stubs(runner, commandlets)
    if not stubs:
        return
    print("plugin variables:")
    for line in format_var_stub_columns(stubs):
        print(line)


def loaded_plugin_var_stubs(runner: Runner, commandlets: Sequence[str]) -> list[str]:
    """Return alphabetized `var=` stubs for variables declared by commandlets."""
    stubs: set[str] = set()
    for commandlet in commandlets:
        plugin = runner.registry.get(commandlet)
        stubs.update(f"{option.name}=" for option in plugin.spec.options)
        provider_scope = provider_scope_for(runner.registry.variable_scope(commandlet))
        stubs.update(f"{provider_scope}.{name}=" for name in plugin.spec.provider_variables)
        stubs.update(f"{provider_scope}.{name}=" for name in plugin.spec.secret_provider_variables)
    return sorted(stubs)


def format_var_stub_columns(stubs: Sequence[str], *, columns: int = 3, width: int | None = None) -> list[str]:
    """Render variable stubs in compact columns that fit the terminal width."""
    if not stubs:
        return []
    terminal_width = width or shutil.get_terminal_size(fallback=(80, 24)).columns
    column_count = min(columns, len(stubs))
    while column_count > 1:
        column_width = max(len(stub) for stub in stubs) + 3
        if column_width * column_count <= terminal_width:
            break
        column_count -= 1
    rows = (len(stubs) + column_count - 1) // column_count
    lines: list[str] = []
    for row in range(rows):
        cells = [stubs[index] for index in range(row, len(stubs), rows)]
        padded = [cell.ljust(max(len(stub) for stub in stubs) + 3) for cell in cells[:-1]]
        lines.append("".join([*padded, cells[-1]]))
    return lines


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
