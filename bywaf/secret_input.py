"""Prompt-toolkit helpers for redacted secret entry.

Provides an interactive `[REDACTED]` input block for explicit secret
assignments while keeping plaintext out of the command buffer.

Used by:
- bywaf.completion: adds secret-aware prompt-toolkit key bindings and styling.
- bywaf.repl.shell: transfers hidden secret values to command dispatch."""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false
# pyright: reportInvalidTypeForm=false

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass

from .secrets import REDACTED_VALUE

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


SECRET_INPUT_MODE_VAR = "secret.input-mode"
DEFAULT_SECRET_INPUT_MODE = "block"
SECRET_INPUT_MODES = {"block", "getpass", "plain", "plaintext"}
SECRET_BLOCK_VALUE = REDACTED_VALUE


@dataclass(slots=True)
class PromptSecretSpan:
    """One visible redacted span with a hidden in-memory value."""

    name: str
    start: int
    end: int
    value: str = ""
    focused: bool = True

    def contains(self, position: int) -> bool:
        """Return whether a cursor position is inside this protected span."""
        return self.start <= position <= self.end


class PromptSecretInputState:
    """Mutable state for one prompt-toolkit command line."""

    def __init__(self) -> None:
        self.span: PromptSecretSpan | None = None

    def clear(self) -> None:
        """Forget any hidden secret from the previous prompt."""
        self.span = None

    def focused(self) -> PromptSecretSpan | None:
        """Return the focused secret span, if one is active."""
        return self.span if self.span and self.span.focused else None

    def focus(self) -> None:
        """Focus the protected span."""
        if self.span is not None:
            self.span.focused = True

    def clear_focus(self) -> None:
        """Leave the protected span without deleting its hidden value."""
        if self.span is not None:
            self.span.focused = False

    def focus_span(self, app) -> None:
        """Focus the protected span and hide the normal terminal cursor."""
        self.focus()
        app.output.hide_cursor()
        app.invalidate()

    def leave_after(self, buffer, app) -> None:
        """Move the cursor after the protected span."""
        if self.span is not None:
            buffer.cursor_position = self.span.end
        self.clear_focus()
        app.output.show_cursor()
        app.invalidate()

    def leave_before(self, buffer, app) -> None:
        """Move the cursor before the protected span."""
        if self.span is not None:
            buffer.cursor_position = max(0, self.span.start - 1)
        self.clear_focus()
        app.output.show_cursor()
        app.invalidate()

    def open_span_if_needed(self, buffer) -> None:
        """Replace an explicit empty secret assignment with `[REDACTED]`."""
        name = open_secret_assignment_name(buffer.document.text_before_cursor)
        if name is None:
            return
        start = buffer.cursor_position
        buffer.insert_text(SECRET_BLOCK_VALUE, move_cursor=True)
        self.span = PromptSecretSpan(name=name, start=start, end=start + len(SECRET_BLOCK_VALUE))
        buffer.cursor_position = self.span.start

    def cursor_relation(self, document: Document) -> str:
        """Return the cursor location relative to the active span."""
        if self.span is None:
            return "none"
        pos = document.cursor_position
        if pos == self.span.start - 1:
            return "left-adjacent"
        if pos < self.span.start:
            return "before"
        if pos == self.span.start:
            return "start"
        if self.span.start < pos < self.span.end:
            return "inside"
        if pos == self.span.end:
            return "end"
        if pos == self.span.end + 1:
            return "right-adjacent"
        return "after"

    def drop_span(self, buffer) -> None:
        """Remove the visible redacted span and forget the hidden value."""
        if self.span is None:
            return
        text = buffer.text
        buffer.text = text[: self.span.start] + text[self.span.end :]
        buffer.cursor_position = min(buffer.cursor_position, len(buffer.text))
        self.clear()

    def forget_if_editing_prefix(self, buffer) -> None:
        """Drop the secret if visible edits invalidate the secret assignment."""
        if self.span is not None and buffer.cursor_position <= self.span.start:
            self.drop_span(buffer)

    def delete_before_cursor(self, buffer) -> None:
        """Backspace safely around a protected secret span."""
        self.forget_if_editing_prefix(buffer)
        buffer.delete_before_cursor(count=1)

    def delete_at_cursor(self, buffer) -> None:
        """Delete safely around a protected secret span."""
        if self.span is not None and buffer.cursor_position < self.span.start:
            self.drop_span(buffer)
        buffer.delete(count=1)

    def values_for_command(self, text: str) -> dict[str, str]:
        """Return hidden secret values that correspond to a submitted line."""
        if self.span is None:
            return {}
        visible = text[self.span.start : self.span.end]
        if visible != SECRET_BLOCK_VALUE:
            return {}
        return {self.span.name: self.span.value}


class PromptSecretLexer(Lexer):
    """Color the protected `[REDACTED]` span."""

    def __init__(self, state: PromptSecretInputState) -> None:
        self.state = state

    def lex_document(self, document: Document):
        def get_line(lineno: int):
            text = document.lines[lineno]
            span = self.state.span
            if lineno != 0 or span is None:
                return [("", text)]
            fragments = []
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
        if not self.state.focused():
            self.wrapped.show_cursor()

    def hide_cursor(self) -> None:
        self.wrapped.hide_cursor()

    def __getattr__(self, name: str):
        return getattr(self.wrapped, name)


def prompt_secret_key_bindings(state: PromptSecretInputState, enabled: Callable[[], bool] | None = None):
    """Return key bindings that keep secret text out of the prompt buffer."""
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
        if enabled is None or enabled():
            state.open_span_if_needed(buffer)
        if state.focused():
            event.app.output.hide_cursor()
        event.app.invalidate()

    @bindings.add("left", eager=True)
    def _left(event) -> None:
        buffer = event.current_buffer
        span = state.span
        if span is None:
            buffer.cursor_left(count=1)
            return
        if span.focused:
            state.leave_before(buffer, event.app)
            return
        relation = state.cursor_relation(buffer.document)
        if relation == "end":
            state.focus_span(event.app)
            return
        if relation == "inside":
            buffer.cursor_position = max(0, span.start - 1)
            return
        buffer.cursor_left(count=1)

    @bindings.add("right", eager=True)
    def _right(event) -> None:
        buffer = event.current_buffer
        span = state.span
        if span is None:
            buffer.cursor_right(count=1)
            return
        if span.focused:
            state.leave_after(buffer, event.app)
            return
        relation = state.cursor_relation(buffer.document)
        if relation in {"start", "left-adjacent"}:
            state.focus_span(event.app)
            return
        if relation == "inside":
            buffer.cursor_position = span.end
            return
        buffer.cursor_right(count=1)

    @bindings.add("backspace", filter=span_focused, eager=True)
    @bindings.add("c-h", filter=span_focused, eager=True)
    def _clear_secret(event) -> None:
        span = state.focused()
        if span is not None:
            span.value = ""
            event.app.invalidate()

    @bindings.add("backspace", eager=True)
    @bindings.add("c-h", eager=True)
    def _backspace(event) -> None:
        buffer = event.current_buffer
        span = state.span
        if span is not None and state.cursor_relation(buffer.document) == "end":
            state.focus_span(event.app)
            span.value = ""
            event.app.invalidate()
            return
        state.delete_before_cursor(buffer)

    @bindings.add("delete", filter=span_focused, eager=True)
    def _clear_secret_delete(event) -> None:
        span = state.focused()
        if span is not None:
            span.value = ""
            event.app.invalidate()

    @bindings.add("delete", eager=True)
    def _delete(event) -> None:
        buffer = event.current_buffer
        span = state.span
        if span is not None and state.cursor_relation(buffer.document) == "start":
            state.focus_span(event.app)
            span.value = ""
            event.app.invalidate()
            return
        state.delete_at_cursor(buffer)

    @bindings.add("escape", filter=span_focused, eager=True)
    def _leave_secret_focus(event) -> None:
        state.leave_after(event.current_buffer, event.app)

    @bindings.add(Keys.Any, filter=span_focused, eager=True)
    def _secret_text(event) -> None:
        span = state.focused()
        key = event.key_sequence[0].key
        data = event.key_sequence[0].data
        if key in {"tab", "c-i"} or data == "\t":
            state.leave_after(event.current_buffer, event.app)
            return
        if key == "enter" or data in {"\r", "\n"}:
            state.leave_after(event.current_buffer, event.app)
            event.current_buffer.validate_and_handle()
            return
        if span is not None and data and data.isprintable():
            span.value += data
            event.app.invalidate()

    return bindings


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


def open_secret_assignment_name(text_before_cursor: str) -> str | None:
    """Return the variable name for an explicit empty secret assignment."""
    if not text_before_cursor.endswith("="):
        return None
    left = text_before_cursor[:-1]
    try:
        tokens = shlex.split(left)
    except ValueError:
        return None
    if not tokens or tokens[0] != "var":
        return None
    if len(tokens) >= 3 and tokens[-2] == "--secret":
        return tokens[-1]
    if len(tokens) >= 3 and tokens[-1] == "--secret":
        return tokens[-2]
    return None
