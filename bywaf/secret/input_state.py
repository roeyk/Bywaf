"""Prompt secret-span state and assignment parsing.

Used by: `secret.input` key bindings and prompt rendering. The classes here
own the hidden in-memory value for one redacted prompt span; prompt-toolkit UI
code decides how key events focus, edit, or leave that span.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any

from ..command.names import VARIABLE_COMMANDS
from .store import REDACTED_VALUE

SECRET_BLOCK_VALUE = REDACTED_VALUE


@dataclass(slots=True)
class PromptSecretSpan:
    """One visible redacted span with a hidden in-memory value.

    Constructed by: `PromptSecretInputState.open_span_if_needed()` when the
    operator types an explicit empty secret assignment such as
    `set --secret name=`.

    Consumed by: prompt lexers, key handlers, and REPL dispatch state to keep
    plaintext out of the visible command buffer.
    """

    name: str
    start: int
    end: int
    value: str = ""
    focused: bool = True

    def contains(self, position: int) -> bool:
        """Return whether a cursor position is inside this protected span."""
        return self.start <= position <= self.end


class PromptSecretInputState:
    """Mutable state for one prompt-toolkit command line.

    Constructed by: `completion.facade.make_prompt_session_kwargs()`.

    Consumed by: `secret.input.prompt_secret_key_bindings()`,
    `completion.prompt.BywafPromptLexer`, and REPL dispatch code that reads
    hidden secret values after the visible command line is submitted.
    """

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

    def focus_span(self, app: Any) -> None:
        """Focus the protected span and hide the normal terminal cursor."""
        self.focus()
        app.output.hide_cursor()
        app.invalidate()

    def leave_after(self, buffer: Any, app: Any) -> None:
        """Move the cursor after the protected span."""
        if self.span is not None:
            buffer.cursor_position = self.span.end
        self.clear_focus()
        app.output.show_cursor()
        app.invalidate()

    def leave_before(self, buffer: Any, app: Any) -> None:
        """Move the cursor before the protected span."""
        if self.span is not None:
            buffer.cursor_position = max(0, self.span.start - 1)
        self.clear_focus()
        app.output.show_cursor()
        app.invalidate()

    def open_span_if_needed(self, buffer: Any) -> None:
        """Replace an explicit empty secret assignment with `[REDACTED]`."""
        name = open_secret_assignment_name(buffer.document.text_before_cursor)
        if name is None:
            return
        # The visible command line receives only a fixed redaction token. The
        # actual typed secret lives in PromptSecretSpan.value until dispatch.
        start = buffer.cursor_position
        buffer.insert_text(SECRET_BLOCK_VALUE, move_cursor=True)
        self.span = PromptSecretSpan(name=name, start=start, end=start + len(SECRET_BLOCK_VALUE))
        buffer.cursor_position = self.span.start

    def cursor_relation(self, document: Any) -> str:
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

    def drop_span(self, buffer: Any) -> None:
        """Remove the visible redacted span and forget the hidden value."""
        if self.span is None:
            return
        text = buffer.text
        buffer.text = text[: self.span.start] + text[self.span.end :]
        buffer.cursor_position = min(buffer.cursor_position, len(buffer.text))
        self.clear()

    def forget_if_editing_prefix(self, buffer: Any) -> None:
        """Drop the secret if visible edits invalidate the secret assignment."""
        if self.span is not None and buffer.cursor_position <= self.span.start:
            self.drop_span(buffer)

    def delete_before_cursor(self, buffer: Any) -> None:
        """Backspace safely around a protected secret span."""
        self.forget_if_editing_prefix(buffer)
        buffer.delete_before_cursor(count=1)

    def delete_at_cursor(self, buffer: Any) -> None:
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


def open_secret_assignment_name(text_before_cursor: str) -> str | None:
    """Return the variable name for an explicit empty secret assignment.

    Called by: `PromptSecretInputState.open_span_if_needed()` when the operator
    types `=` in the prompt.
    """
    try:
        tokens = shlex.split(text_before_cursor)
    except ValueError:
        return None
    if not tokens or tokens[0] not in VARIABLE_COMMANDS:
        return None
    if len(tokens) >= 3 and tokens[-2] == "--secret":
        assignment = tokens[-1]
    elif len(tokens) >= 3 and tokens[-1] == "--secret":
        assignment = tokens[-2]
    else:
        return None
    if not assignment.endswith("="):
        return None
    name = assignment[:-1]
    return name or None
