"""REPL variable, secret, and active-context commands.

Provides `set`, `setg`, `vars`, and `use`, including commandlet-scoped variable
resolution and secret-reference storage.

Used by:
- bywaf.repl.commands: registers variable/context handlers.
- bywaf.repl.command.plugins: switches context after plugin loading.
"""

from __future__ import annotations

import getpass
import shlex
import sys
from typing import TYPE_CHECKING

from ...command.names import SET_COMMAND, SETG_COMMAND
from ...runner import Runner
from ...secret.askpass import (
    ASKPASS_MODE,
    AskpassCancelled,
    AskpassUnavailable,
    PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE,
    read_askpass_secret,
)
from ...secret.input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_BLOCK_VALUE,
    SECRET_INPUT_MODES,
    SECRET_INPUT_MODE_VAR,
    effective_secret_input_mode,
    normalize_secret_input_mode,
)
from ...secret.store import load_or_create_fingerprint_key
from ..display import format_var_assignment

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
            key=load_or_create_fingerprint_key(),
            source=source,
        )
        runner.registry.varstore.set(resolved_key, secret_ref.ref)
        runner.db.store_secret(secret_ref, cleaned_value)
        if not runner.db.encrypted:
            print(f"warning: storing secret variable {resolved_key} in plaintext database {runner.db.path}")
        print(format_var_assignment(runner, resolved_key, secret_ref.ref))
        warn_if_pending_catalog_variable(runner, resolved_key)
        return
    runner.registry.varstore.set(resolved_key, cleaned_value)
    warn_if_pending_catalog_variable(runner, resolved_key)


def configured_secret_input_mode(runner: Runner) -> str:
    """Return the configured secret input mode from the variable store."""
    return runner.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE) or DEFAULT_SECRET_INPUT_MODE


def read_secret_value(name: str, *, mode: str | None = None) -> str:
    """Read one secret value without echoing it to the terminal."""
    prompt = f"Secret for {name}: "
    warn_if_unknown_secret_input_mode(mode)
    configured_mode = normalize_secret_input_mode(mode)
    effective_mode = effective_secret_input_mode(mode)
    if effective_mode == ASKPASS_MODE:
        try:
            return read_askpass_secret(prompt)
        except AskpassCancelled as exc:
            raise ValueError("secret prompt cancelled") from exc
        except AskpassUnavailable as exc:
            if configured_mode in {DEFAULT_SECRET_INPUT_MODE, ASKPASS_MODE}:
                print(
                    f"warning: askpass secret input unavailable ({exc}); falling back to terminal prompt",
                    file=sys.stderr,
                )
                return getpass.getpass(prompt)
            raise ValueError("askpass secret input is unavailable") from exc
    if effective_mode in {PLAIN_SECRET_INPUT_MODE, PLAINTEXT_SECRET_INPUT_MODE}:
        return input(prompt)
    return getpass.getpass(prompt)


def warn_if_unknown_secret_input_mode(mode: str | None) -> None:
    """Warn when a configured secret input mode is unsupported."""
    normalized = str(mode or DEFAULT_SECRET_INPUT_MODE).strip().casefold()
    if normalized not in SECRET_INPUT_MODES:
        print(
            "warning: unsupported input mode; falling back to auto",
            file=sys.stderr,
        )


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


def warn_if_pending_catalog_variable(runner: Runner, key: str) -> None:
    """Warn when storing a commandlet-scoped variable before that commandlet is loaded."""
    if "/" not in key or "." not in key:
        return
    if key.startswith("display/"):
        return
    scope, variable = key.rsplit(".", 1)
    if not scope or not variable or runner.registry.has_commandlet(scope):
        return
    print(f"warning: {scope} is not loaded; storing {key} until that commandlet is loaded")


def set_active_context(runner: Runner, state: ShellState, target: str) -> None:
    """Set the active commandlet context for short variable assignments."""
    if target == "global":
        state.active_context = None
        if state.completer is not None:
            state.completer.active_context = None
        print("using global")
        return
    if not runner.registry.has_commandlet(target):
        # A provider may expose a default commandlet. If it exposes multiple and
        # none is marked default, require the user to choose explicitly.
        default = runner.registry.provider_default(target)
        if default is None:
            commandlets = runner.registry.provider_commandlet_names(target)
            if commandlets:
                choices = ", ".join(commandlets)
                raise ValueError(f"{target} exposes multiple commandlets; choose one: {choices}")
            raise ValueError(f"unknown commandlet context: {target}")
        target = default
    commandlet = runner.registry.variable_scope(target)
    state.active_context = commandlet
    if state.completer is not None:
        state.completer.active_context = commandlet
    print(f"using {commandlet}")


def resolve_var_key(runner: Runner, state: ShellState, key: str) -> str:
    """Resolve unqualified variable keys through the active `use` context."""
    if key.startswith("global."):
        return key
    if key.startswith("display/"):
        return key
    if "/" in key and "." in key:
        # Fully-qualified commandlet variables use catalog/path.command_var.
        # Preserve unloaded catalog variables so they can apply after loading.
        scope, name = key.rsplit(".", 1)
        if runner.registry.has_commandlet(scope):
            return f"{runner.registry.variable_scope(scope)}.{name}"
        return key
    if "." in key:
        scope, name = key.rsplit(".", 1)
        if runner.registry.has_commandlet(scope):
            return f"{runner.registry.variable_scope(scope)}.{name}"
    if state.active_context:
        # In a `use` context, bare `set timeout=5` means
        # set <active-commandlet>.timeout=5.
        return f"{state.active_context}.{key}"
    return key
