"""Prompt-toolkit helpers for redacted secret entry.

Provides an interactive `[REDACTED]` input block for explicit secret
assignments while keeping plaintext out of the command buffer.

Used by:
- bywaf.completion: adds secret-aware prompt-toolkit key bindings and styling.
- bywaf.repl.shell: transfers hidden secret values to command dispatch."""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false
# pyright: reportInvalidTypeForm=false

from __future__ import annotations

from collections.abc import Callable

from .askpass import (
    ASKPASS_MODE as ASKPASS_MODE,
    AUTO_SECRET_INPUT_MODE as AUTO_SECRET_INPUT_MODE,
    BLOCK_SECRET_INPUT_MODE as BLOCK_SECRET_INPUT_MODE,
    GETPASS_SECRET_INPUT_MODE as GETPASS_SECRET_INPUT_MODE,
    PLAIN_SECRET_INPUT_MODE as PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE as PLAINTEXT_SECRET_INPUT_MODE,
    desktop_askpass_available as desktop_askpass_available,
)
from .input_modes import DEFAULT_SECRET_INPUT_MODE as DEFAULT_SECRET_INPUT_MODE
from .input_modes import SECRET_INPUT_MODES as SECRET_INPUT_MODES
from .input_modes import SECRET_INPUT_MODE_VAR as SECRET_INPUT_MODE_VAR
from .input_modes import normalize_secret_input_mode as normalize_secret_input_mode
from .input_state import SECRET_BLOCK_VALUE as SECRET_BLOCK_VALUE
from .input_state import PromptSecretInputState as PromptSecretInputState
from .input_state import PromptSecretSpan as PromptSecretSpan
from .input_state import open_secret_assignment_name as open_secret_assignment_name

try:
    from prompt_toolkit.document import Document
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.keys import Keys
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.output.defaults import create_output
    from prompt_toolkit.styles import Style
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    Condition = None
    Document = object
    KeyBindings = None
    Keys = None
    Lexer = object
    Style = None
    create_output = None


def effective_secret_input_mode(value: object | None) -> str:
    """Resolve auto mode using this facade's patchable askpass probe.

    Called by: completion and REPL setup code. Tests patch
    `bywaf.secret.input.desktop_askpass_available`, so this public facade keeps
    the decision point here even though shared constants live in
    `secret.input_modes`.
    """
    mode = normalize_secret_input_mode(value)
    if mode == AUTO_SECRET_INPUT_MODE:
        return ASKPASS_MODE if desktop_askpass_available() else BLOCK_SECRET_INPUT_MODE
    return mode


class PromptSecretLexer(Lexer):
    """Color the protected `[REDACTED]` span.

    Constructed by: prompt-toolkit setup when secret-block input is enabled.
    Consumed by: prompt rendering to style the visible placeholder while the
    real secret stays in `PromptSecretInputState`.
    """

    def __init__(self, state: PromptSecretInputState) -> None:
        self.state = state

    def lex_document(self, document: Document):
        """Return a prompt-toolkit line lexer for the current document."""
        def get_line(lineno: int):
            text = document.lines[lineno]
            span = self.state.span
            if lineno != 0 or span is None:
                return [("", text)]
            fragments = []
            # Split the single-line prompt into normal text before/after the
            # placeholder and a styled protected span in the middle.
            if span.start > 0:
                fragments.append(("", text[: span.start]))
            style = "class:secret.focused" if span.focused else "class:secret.inactive"
            fragments.append((style, text[span.start : span.end]))
            if span.end < len(text):
                fragments.append(("", text[span.end :]))
            return fragments

        return get_line


class SecretCursorOutput:
    """Output proxy that suppresses the cursor while a secret block is focused."""

    def __init__(self, wrapped, state: PromptSecretInputState) -> None:
        self.wrapped = wrapped
        self.state = state

    def show_cursor(self) -> None:
        """Show cursor during terminal secret input."""
        if not self.state.focused():
            self.wrapped.show_cursor()

    def hide_cursor(self) -> None:
        """Hide cursor during terminal secret input."""
        self.wrapped.hide_cursor()

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


def prompt_secret_key_bindings(state: PromptSecretInputState, enabled: Callable[[], bool] | None = None):
    """Return key bindings that keep secret text out of the prompt buffer.

    Called by: completion prompt setup. The handlers below intercept cursor and
    editing keys while a redacted span is focused.
    """
    if KeyBindings is None or Condition is None or Keys is None:
        return None
    bindings = KeyBindings()

    @Condition
    def span_focused() -> bool:
        return state.focused() is not None

    @bindings.add("=", eager=True)
    def _open_secret_block(event) -> None:
        buffer = event.current_buffer
        buffer.insert_text("=")
        # Opening a block is triggered by `set --secret name=` style input. From
        # here, character keys update hidden state instead of the visible buffer.
        if enabled is None or enabled():
            state.open_span_if_needed(buffer)
        if state.focused():
            event.app.output.hide_cursor()
        event.app.invalidate()

    @bindings.add("left", eager=True)
    def _left(event) -> None:
        handle_secret_left(state, event.current_buffer, event.app)

    @bindings.add("right", eager=True)
    def _right(event) -> None:
        handle_secret_right(state, event.current_buffer, event.app)

    @bindings.add("backspace", filter=span_focused, eager=True)
    @bindings.add("c-h", filter=span_focused, eager=True)
    def _clear_secret(event) -> None:
        clear_focused_secret(state, event.app)

    @bindings.add("backspace", eager=True)
    @bindings.add("c-h", eager=True)
    def _backspace(event) -> None:
        handle_secret_backspace(state, event.current_buffer, event.app)

    @bindings.add("delete", filter=span_focused, eager=True)
    def _clear_secret_delete(event) -> None:
        clear_focused_secret(state, event.app)

    @bindings.add("delete", eager=True)
    def _delete(event) -> None:
        handle_secret_delete(state, event.current_buffer, event.app)

    @bindings.add("escape", filter=span_focused, eager=True)
    def _leave_secret_focus(event) -> None:
        state.leave_after(event.current_buffer, event.app)

    @bindings.add(Keys.Any, filter=span_focused, eager=True)
    def _secret_text(event) -> None:
        key = event.key_sequence[0].key
        data = event.key_sequence[0].data
        handle_focused_secret_text(state, event.current_buffer, event.app, key, data)

    return bindings


def handle_secret_left(state: PromptSecretInputState, buffer, app) -> None:
    """Move left across or into a protected secret span."""
    span = state.span
    if span is None:
        buffer.cursor_left(count=1)
        return
    # When focused, arrow keys leave the protected block as a unit. When not
    # focused, landing on either edge focuses the block rather than exposing
    # internal cursor positions.
    if span.focused:
        state.leave_before(buffer, app)
        return
    relation = state.cursor_relation(buffer.document)
    if relation == "end":
        state.focus_span(app)
        return
    if relation == "inside":
        buffer.cursor_position = max(0, span.start - 1)
        return
    buffer.cursor_left(count=1)


def handle_secret_right(state: PromptSecretInputState, buffer, app) -> None:
    """Move right across or into a protected secret span."""
    span = state.span
    if span is None:
        buffer.cursor_right(count=1)
        return
    # Symmetric handling to handle_secret_left(): the visible placeholder is
    # navigated as one editable object with hidden backing storage.
    if span.focused:
        state.leave_after(buffer, app)
        return
    relation = state.cursor_relation(buffer.document)
    if relation in {"start", "left-adjacent"}:
        state.focus_span(app)
        return
    if relation == "inside":
        buffer.cursor_position = span.end
        return
    buffer.cursor_right(count=1)


def clear_focused_secret(state: PromptSecretInputState, app) -> None:
    """Clear hidden text from the focused secret span."""
    span = state.focused()
    if span is not None:
        span.value = ""
        app.invalidate()


def handle_secret_backspace(state: PromptSecretInputState, buffer, app) -> None:
    """Backspace around or inside a protected secret span."""
    span = state.span
    if span is not None and state.cursor_relation(buffer.document) == "end":
        state.focus_span(app)
        span.value = ""
        app.invalidate()
        return
    state.delete_before_cursor(buffer)


def handle_secret_delete(state: PromptSecretInputState, buffer, app) -> None:
    """Delete around or inside a protected secret span."""
    span = state.span
    if span is not None and state.cursor_relation(buffer.document) == "start":
        state.focus_span(app)
        span.value = ""
        app.invalidate()
        return
    state.delete_at_cursor(buffer)


def handle_focused_secret_text(
    state: PromptSecretInputState,
    buffer,
    app,
    key: str,
    data: str,
) -> None:
    """Handle a key press while the secret span is focused."""
    span = state.focused()
    # Tab/enter leave the protected input mode; printable keys append to the
    # hidden value without mutating the visible prompt buffer.
    if key in {"tab", "c-i"} or data == "\t":
        state.leave_after(buffer, app)
        return
    if key == "enter" or data in {"\r", "\n"}:
        state.leave_after(buffer, app)
        buffer.validate_and_handle()
        return
    if span is not None and data and data.isprintable():
        span.value += data
        app.invalidate()


def prompt_secret_style():
    """Return styles for redacted secret blocks."""
    if Style is None:
        return None
    return Style.from_dict(
        {
            "secret.focused": "bg:ansired #ffffff blink bold",
            "secret.inactive": "bg:#5f0000 #ffffff",
        }
    )


def prompt_secret_output(state: PromptSecretInputState):
    """Return an output wrapper that hides the cursor inside secret blocks."""
    if create_output is None:
        return None
    return SecretCursorOutput(create_output(), state)
