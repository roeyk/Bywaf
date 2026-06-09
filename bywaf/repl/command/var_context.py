"""Active variable-context and variable-key resolution helpers.

Used by: `repl.command.vars` and plugin-loading commands that switch the
operator's active variable scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...runner import Runner

if TYPE_CHECKING:
    from ..state import ShellState


def warn_if_pending_catalog_variable(runner: Runner, key: str) -> None:
    """Warn when storing a commandlet-scoped variable before that commandlet is loaded.

    Called by: `set_var()` after storing a variable.
    """
    if "/" not in key or "." not in key:
        return
    if key.startswith("display/"):
        return
    scope, variable = key.rsplit(".", 1)
    if not scope or not variable or runner.registry.has_commandlet(scope):
        return
    print(f"warning: {scope} is not loaded; storing {key} until that commandlet is loaded")


def set_active_context(runner: Runner, state: ShellState, target: str) -> None:
    """Set the active commandlet context for short variable assignments.

    Called by: `use` and by plugin-loading commands after loading a provider.
    """
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
    """Resolve unqualified variable keys through the active `use` context.

    Called by: variable show/set handlers before touching the variable store.
    """
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
