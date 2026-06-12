"""Prompt-toolkit completion keybinding helpers.

Used by:
- completion engines and prompt UI helpers for interactive command entry.
"""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false

from __future__ import annotations

from typing import Any

try:
    from prompt_toolkit.enums import DEFAULT_BUFFER
    from prompt_toolkit.filters import has_completions
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding import merge_key_bindings
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    DEFAULT_BUFFER = "DEFAULT_BUFFER"
    has_completions = None
    KeyBindings = None
    merge_key_bindings = None


COMPLETION_SELECT_KEY_VAR = "completion.select-key"
COMPLETION_WASD_SELECTION_VAR = "completion.wasd-selection"
DEFAULT_COMPLETION_SELECT_KEY = "c-space"


def merge_prompt_key_bindings(*bindings):
    """Merge optional prompt-toolkit key binding sets."""
    present = [binding for binding in bindings if binding is not None]
    if not present:
        return None
    if len(present) == 1 or merge_key_bindings is None:
        return present[0]
    return merge_key_bindings(present)


def completion_key_bindings(completer: Any):
    """Return prompt-toolkit keybindings for completion selection."""
    if KeyBindings is None or has_completions is None:
        return None
    bindings = KeyBindings()
    select_key = completion_select_key(completer)

    try:
        register_select_binding(bindings, select_key)
    except ValueError:
        register_select_binding(bindings, DEFAULT_COMPLETION_SELECT_KEY)
    if wasd_selection_enabled(completer):
        register_wasd_bindings(bindings)

    return bindings


def register_select_binding(bindings, select_key: str) -> None:
    """Register the configured completion-selection-mode key."""

    @bindings.add(select_key)
    def _select_completion(event) -> None:
        enter_completion_selection_mode(event)

    @bindings.add("enter", filter=has_completions)
    def _accept_completion(event) -> None:
        apply_current_completion(event)

    @bindings.add("tab", filter=has_completions)
    def _accept_with_tab(event) -> None:
        apply_current_completion(event)

    @bindings.add("right", filter=has_completions)
    def _right_completion(event) -> None:
        event.current_buffer.complete_next()

    @bindings.add("left", filter=has_completions)
    def _left_completion(event) -> None:
        event.current_buffer.complete_previous()

    @bindings.add("escape", filter=has_completions, eager=True)
    def _cancel_completion(event) -> None:
        cancel_completion_menu(event)


def register_wasd_bindings(bindings) -> None:
    """Register optional WASD completion-menu navigation keys."""

    @bindings.add("w", filter=has_completions)
    def _previous_completion(event) -> None:
        event.current_buffer.complete_previous()

    @bindings.add("a", filter=has_completions)
    def _left_completion(event) -> None:
        event.current_buffer.complete_previous()

    @bindings.add("s", filter=has_completions)
    def _next_completion(event) -> None:
        event.current_buffer.complete_next()

    @bindings.add("d", filter=has_completions)
    def _right_completion(event) -> None:
        event.current_buffer.complete_next()


def apply_current_completion(event) -> None:
    """Accept the highlighted completion, or the first completion if none selected."""
    buffer = event.app.layout.get_buffer_by_name(DEFAULT_BUFFER)
    if buffer is None or buffer.complete_state is None:
        return
    completion = buffer.complete_state.current_completion
    if completion is None and buffer.complete_state.completions:
        completion = buffer.complete_state.completions[0]
    if completion is not None:
        buffer.apply_completion(completion)


def cancel_completion_menu(event) -> None:
    """Dismiss an active prompt-toolkit completion menu."""
    event.current_buffer.cancel_completion()


def enter_completion_selection_mode(event) -> None:
    """Open the completion menu and select the first item for navigation."""
    buffer = event.current_buffer
    if buffer.complete_state is None:
        buffer.start_completion(select_first=True)
        return
    if buffer.complete_state.current_completion is None and buffer.complete_state.completions:
        buffer.go_to_completion(0)


def wasd_selection_enabled(completer: Any) -> bool:
    """Return whether optional WASD completion navigation is enabled."""
    value = completer.registry.varstore.get(COMPLETION_WASD_SELECTION_VAR, "false")
    return framework_bool(value, default=False)


def completion_select_key(completer: Any) -> str:
    """Return the configured prompt-toolkit key name for selection."""
    value = completer.registry.varstore.get(COMPLETION_SELECT_KEY_VAR, DEFAULT_COMPLETION_SELECT_KEY)
    key = str(value).strip()
    if key.casefold() in {"", "none", "off", "disabled"}:
        return DEFAULT_COMPLETION_SELECT_KEY
    return key


def framework_bool(value: str | None, *, default: bool) -> bool:
    """Parse a shell variable as a framework boolean."""
    if value is None:
        return default
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


def completion_select_key_display(completer: Any) -> str:
    """Return a human-readable label for the configured selection key."""
    key = completion_select_key(completer)
    if key == "c-space":
        return "Ctrl-Space"
    if key.startswith("c-") and len(key) > 2:
        return f"Ctrl-{key[2:].upper()}"
    return key
