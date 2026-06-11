"""REPL variable, secret, and active-context commands.

Provides `set`, `setg`, `vars`, and `use`, including commandlet-scoped variable
resolution and secret-reference storage.

Used by:
- bywaf.repl.commands: registers variable/context handlers.
- bywaf.repl.command.plugins: switches context after plugin loading.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from ...command.names import SET_COMMAND, SETG_COMMAND
from ...runner import Runner
from ...secret.input import SECRET_BLOCK_VALUE
from ...secret.store import load_fingerprint_key
from ..display import format_var_assignment
from .var_context import resolve_var_key, set_active_context, warn_pending_catalog_var
from .var_secrets import configured_secret_input_mode, read_secret_value

if TYPE_CHECKING:
    from ..state import ShellState


def handle_use_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the active variable context."""
    del line
    if rest is None:
        print(state.active_context or "global")
    else:
        set_active_context(runner, state, rest)
    return None


def handle_vars_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """List, show, or set variables."""
    del line
    if rest is None:
        print_vars(runner, state)
    elif "=" in rest:
        set_var(runner, state, rest)
    else:
        print_var(runner, state, rest)
    return None


def handle_setg_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Set or show one explicitly global variable."""
    del line
    if rest is None:
        print("usage: setg [--secret] name=value")
    elif "=" in rest:
        set_var(runner, state, globalize_setg(rest), source=SETG_COMMAND)
    else:
        print_var(runner, state, f"global.{rest.strip()}")
    return None


def print_vars(runner: Runner, state: ShellState) -> None:
    """Print session variables in stable key order."""
    active_prefix = f"{state.active_context}." if state.active_context else ""
    active_items: list[tuple[str, str]] = []
    other_items: list[tuple[str, str]] = []
    for key, value in runner.registry.varstore.items():
        if active_prefix and key.startswith(active_prefix):
            active_items.append((key, value))
        else:
            other_items.append((key, value))
    print_var_list("Variables", other_items, runner)
    if active_prefix:
        print()
        print_var_list(f"In-focus variables ({state.active_context})", active_items, runner)


def print_var_list(heading: str, items: list[tuple[str, str]], runner: Runner) -> None:
    """Print one alphabetized variable section."""
    print(f"{heading}:")
    for key, value in sorted(items):
        print(format_var_assignment(runner, key, value))


def print_var(runner: Runner, state: ShellState, name: str) -> None:
    """Print one session variable after applying active-context scoping."""
    key = resolve_var_key(runner, state, name.strip())
    value = runner.registry.varstore.get(key)
    if value is None:
        print(f"error: variable not set: {key}")
        return
    print(format_var_assignment(runner, key, value))


def set_var(runner: Runner, state: ShellState, assignment: str, *, source: str = SET_COMMAND) -> None:
    """Set a REPL variable, keeping explicitly secret values out of varstore."""
    assignment, explicit_secret = parse_var_assignment_flags(assignment)
    key, value = assignment.split("=", 1)
    resolved_key = resolve_var_key(runner, state, key.strip())
    cleaned_value = clean_var_value(value)
    if explicit_secret:
        # Secrets store a fingerprinted reference in varstore and the cleartext
        # in the DB secret table. This keeps command rendering/audit output from
        # exposing the original value.
        hidden_values = getattr(state, "secret_values", {})
        hidden_value = hidden_values.get(resolved_key) or hidden_values.get(key.strip())
        if cleaned_value == SECRET_BLOCK_VALUE and hidden_value is not None:
            cleaned_value = hidden_value
        elif cleaned_value == "":
            cleaned_value = read_secret_value(resolved_key, mode=configured_secret_input_mode(runner))
        secret_ref = runner.registry.secrets.put(
            resolved_key,
            cleaned_value,
            key=load_fingerprint_key(),
            source=source,
        )
        runner.registry.varstore.set(resolved_key, secret_ref.ref)
        runner.db.store_secret(secret_ref, cleaned_value)
        if not runner.db.encrypted:
            print(f"warning: storing secret variable {resolved_key} in plaintext database {runner.db.path}")
        print(format_var_assignment(runner, resolved_key, secret_ref.ref))
        warn_pending_catalog_var(runner, resolved_key)
        return
    runner.registry.varstore.set(resolved_key, cleaned_value)
    warn_pending_catalog_var(runner, resolved_key)


def clean_var_value(value: str) -> str:
    """Normalize one `set name=value` value while honoring shell quotes."""
    stripped = value.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    if len(tokens) == 1:
        return tokens[0]
    return stripped


def parse_var_assignment_flags(assignment: str) -> tuple[str, bool]:
    """Return assignment text and whether it requested explicit secret storage."""
    stripped = assignment.strip()
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = []
    if any(token.startswith("--secret=") for token in tokens):
        raise ValueError(f"usage: {SET_COMMAND} [--secret] name=value")
    left, separator, right = stripped.partition("=")
    if separator:
        left_tokens = shlex.split(left)
        if "--secret" in left_tokens:
            key_tokens = [token for token in left_tokens if token != "--secret"]
            if len(key_tokens) != 1:
                raise ValueError(f"usage: {SET_COMMAND} [--secret] name=value")
            return f"{key_tokens[0]}={right}", True
    if stripped.endswith(" --secret"):
        return stripped.removesuffix(" --secret").strip(), True
    return assignment, False


def globalize_setg(assignment: str) -> str:
    """Convert `setg name=value` text to a `global.name=value` assignment."""
    stripped = assignment.strip()
    if stripped.startswith("--secret "):
        prefix = "--secret "
        return f"{prefix}global.{stripped.removeprefix(prefix).strip()}"
    if " --secret" in stripped:
        key_value = stripped.removesuffix(" --secret").strip()
        return f"global.{key_value} --secret"
    return f"global.{stripped}"
