"""Readline and prompt-toolkit completion adapters.

Provides the public Completer API, readline callback behavior, prompt-toolkit
integration, and display formatting for completion menus.

Used by:
- REPL shell: installs interactive completion.
- completion tests and plugins: rely on the stable public completion surface."""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false
# pyright: reportInvalidTypeForm=false

from __future__ import annotations

import readline
import shlex
from collections.abc import Sequence
from os.path import commonprefix
from typing import Any

try:
    from prompt_toolkit.completion import Completion
    from prompt_toolkit.completion import Completer as PromptToolkitCompleterBase
    from prompt_toolkit.enums import DEFAULT_BUFFER
    from prompt_toolkit.filters import has_completions
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding import merge_key_bindings
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.shortcuts.prompt import CompleteStyle
    from prompt_toolkit.styles import Style
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    Completion = None
    PromptToolkitCompleterBase = object
    DEFAULT_BUFFER = "DEFAULT_BUFFER"
    has_completions = None
    HTML = None
    KeyBindings = None
    Lexer = object
    merge_key_bindings = None
    PromptSession = None
    CompleteStyle = None
    Style = None

from .constants import BINARY_OPTION_NAMES, option_is_binary
from .engine import CoreCompleter
from .providers import bundle_candidates, history_candidates, key_candidates
from .resources import (
    complete_at_file_prefix,
    complete_resource_value,
    is_explicit_path,
    preserve_explicit_prefix,
    resource_candidates,
)
from .runtime import runtime_completion_target
from .tokens import positional_index, tokens_after_last_pipe
from .variables import variable_reference_candidates
from ..secret.input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_INPUT_MODES,
    SECRET_INPUT_MODE_VAR,
    PromptSecretInputState,
    PromptSecretLexer,
    prompt_secret_key_bindings,
    prompt_secret_output,
)

# Public re-export surface for this module.  Importers can use
# `from bywaf.completion import ...` without needing to know which helpers live
# in the candidate-generation modules versus this adapter module.  It also
# makes wildcard imports deterministic for tests and older integrations.
__all__ = [
    "BINARY_OPTION_NAMES",
    "BywafPromptLexer",
    "COMPLETION_SELECT_KEY_VAR",
    "COMPLETION_WASD_SELECTION_VAR",
    "DEFAULT_COMPLETION_SELECT_KEY",
    "DEFAULT_SECRET_INPUT_MODE",
    "SECRET_INPUT_MODES",
    "SECRET_INPUT_MODE_VAR",
    "Completer",
    "CoreCompleter",
    "PromptToolkitCompleter",
    "apply_current_completion",
    "build_prompt_session",
    "bundle_candidates",
    "common_completion_prefix",
    "complete_at_file_prefix",
    "complete_resource_value",
    "completion_key_bindings",
    "completion_prefix",
    "completion_results",
    "completion_select_key",
    "completion_select_key_display",
    "completion_wasd_selection_enabled",
    "configure_readline_delimiters",
    "cancel_completion_menu",
    "display_label",
    "enter_completion_selection_mode",
    "format_candidate",
    "framework_bool",
    "history_candidates",
    "install_readline",
    "is_explicit_path",
    "key_candidates",
    "option_is_binary",
    "positional_index",
    "preserve_explicit_prefix",
    "print_completion_menu",
    "prompt_toolkit_available",
    "register_select_completion_binding",
    "register_wasd_completion_bindings",
    "readline",
    "resource_candidates",
    "runtime_completion_target",
    "secret_input_bottom_toolbar",
    "secret_input_mode",
    "should_display_value_only",
    "should_print_completion_menu",
    "tokens_after_last_pipe",
    "variable_reference_candidates",
]

COMPLETION_SELECT_KEY_VAR = "completion.select-key"
COMPLETION_WASD_SELECTION_VAR = "completion.wasd-selection"
DEFAULT_COMPLETION_SELECT_KEY = "c-space"
DISPLAY_STYLE_PREFIX = "display/style."
DISPLAY_VALUE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}value"
DISPLAY_STRING_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}string"
DISPLAY_VARIABLE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}variable"

PROMPT_TOOLKIT_COLOR_NAMES = {
    "black": "ansiblack",
    "red": "ansired",
    "green": "ansigreen",
    "yellow": "ansiyellow",
    "blue": "ansiblue",
    "magenta": "ansimagenta",
    "cyan": "ansicyan",
    "white": "ansiwhite",
    "bright-black": "ansibrightblack",
    "bright-red": "ansibrightred",
    "bright-green": "ansibrightgreen",
    "bright-yellow": "ansibrightyellow",
    "bright-blue": "ansibrightblue",
    "bright-magenta": "ansibrightmagenta",
    "bright-cyan": "ansibrightcyan",
    "bright-white": "ansibrightwhite",
}

PROMPT_TOOLKIT_ATTR_NAMES = {
    "bold",
    "italic",
    "underline",
    "reverse",
}


class Completer(CoreCompleter):
    """Readline adapter around Bywaf's command-aware completion core.

    `CoreCompleter` knows what Bywaf candidates exist.  This subclass translates
    those candidates into the callback protocol expected by Python's `readline`
    module, which asks for one completion candidate at a time by numeric state.
    """

    def complete(self, text: str, state: int) -> str | None:
        """Readline callback: return one candidate per requested state.

        Readline calls this repeatedly with `state == 0`, `state == 1`, and so
        on until it receives `None`.  The callback ignores `text` because Bywaf
        needs the whole input buffer, not only the current token, to complete
        scoped commands, key=value selectors, and pipeline stages.
        """
        del text
        line = readline.get_line_buffer()
        candidates = self.candidates(line)
        common = common_completion_prefix(line, candidates)
        # First prefer extending the token when every candidate shares a longer
        # prefix, so `plugin lo<Tab>` can become `plugin load=` before showing a
        # menu.
        if state == 0 and common:
            return common
        # Readline does not have a rich popup-menu API.  For key=value choices
        # we print a compact value-only menu on the first callback, then let a
        # second Tab cycle through the actual insertion candidates.
        if state == 0 and should_print_completion_menu(line, candidates):
            print_completion_menu(line, candidates)
            return None
        results = completion_results(line, candidates)
        return results[state] if state < len(results) else None

    def format_candidate(self, candidate: str) -> str:
        """Return a readline-formatted candidate."""
        return format_candidate(candidate)

    def format_common_prefix(self, candidate: str) -> str:
        """Return a shared prefix without adding completion suffixes."""
        return candidate


class PromptToolkitCompleter(PromptToolkitCompleterBase):
    """Prompt-toolkit adapter around Bywaf's command-aware completer.

    Prompt-toolkit has a richer completion model than readline: one method can
    yield candidate objects with insertion text, display text, and metadata.
    This adapter keeps candidate discovery in `Completer` while translating the
    result into prompt-toolkit's UI objects.
    """

    def __init__(self, completer: Completer):
        self.completer = completer

    def get_completions(self, document, complete_event: Any):
        """Yield prompt-toolkit Completion objects for the current buffer."""
        del complete_event
        if Completion is None:
            return
        line = document.text_before_cursor
        prefix = completion_prefix(line)
        candidates = self.completer.candidates(line)
        display_value_only = should_display_value_only(prefix, candidates)
        for candidate in candidates:
            yield Completion(
                self.completer.format_candidate(candidate),
                start_position=-len(prefix),
                display=display_label(candidate) if display_value_only else candidate,
                display_meta=self.completer.completion_meta(candidate, line, prefix),
            )


def prompt_toolkit_available() -> bool:
    """Return whether the richer prompt-toolkit REPL can be used."""
    return PromptSession is not None and KeyBindings is not None


def build_prompt_session(completer: Completer):
    """Create a prompt-toolkit session with Bywaf completion behavior.

    The REPL uses this when prompt-toolkit is installed.  The session wires
    together completion, secret-input masking, the bottom toolbar, and custom
    keybindings so the shell can offer a richer UI without changing commandlet
    parsing semantics.
    """
    if not prompt_toolkit_available():
        return None
    assert PromptSession is not None
    assert CompleteStyle is not None
    secret_state = PromptSecretInputState()
    completion_bindings = completion_key_bindings(completer)
    secret_bindings = prompt_secret_key_bindings(secret_state, enabled=lambda: secret_input_mode(completer) == "block")
    key_bindings = merge_prompt_key_bindings(completion_bindings, secret_bindings)
    session_kwargs = {
        "lexer": BywafPromptLexer(completer, secret_state),
        "style": prompt_input_style(),
        "output": prompt_secret_output(secret_state),
    }
    session = PromptSession(
        completer=PromptToolkitCompleter(completer),
        complete_while_typing=False,
        complete_style=CompleteStyle.MULTI_COLUMN,
        reserve_space_for_menu=8,
        bottom_toolbar=lambda: secret_input_bottom_toolbar(secret_state),
        key_bindings=key_bindings,
        **{key: value for key, value in session_kwargs.items() if value is not None},
    )
    # `PromptSession` does not know about Bywaf's secret-input state, but tests
    # and REPL code need access to it.  Attaching it here keeps the state beside
    # the session that owns the corresponding lexer/output objects.
    setattr(session, "secret_state", secret_state)
    return session


class BywafPromptLexer(Lexer):
    """Style live REPL input without changing command parsing semantics.

    Prompt-time styling is intentionally shallow.  It marks variable names,
    the value side of `key=value` tokens, and quoted string values so the
    operator gets immediate visual feedback, while the normal parser remains
    the source of truth.
    """

    def __init__(self, completer: Completer, secret_state: PromptSecretInputState) -> None:
        self.completer = completer
        self.secret_lexer = PromptSecretLexer(secret_state)

    def lex_document(self, document):
        secret_get_line = self.secret_lexer.lex_document(document)

        def get_line(lineno: int):
            fragments = prompt_value_fragments(self.completer, document.lines[lineno])
            return overlay_secret_fragments(fragments, secret_get_line(lineno))

        return get_line


def prompt_value_fragments(completer: Completer, text: str):
    """Return prompt-toolkit fragments for variables, values, and quoted strings."""
    variable_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_VARIABLE_STYLE_VAR, ""))
    value_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_VALUE_STYLE_VAR, ""))
    string_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_STRING_STYLE_VAR, ""))
    if not variable_style and not value_style and not string_style:
        return [("", text)]
    fragments: list[tuple[str, str]] = []
    index = 0
    while index < len(text):
        equals = next_unquoted_equals(text, index)
        if equals is None:
            append_variable_reference_fragments(fragments, text[index:], variable_style)
            break
        append_assignment_key_fragments(fragments, text[index:equals], variable_style)
        fragments.append(("", "="))
        value_end = value_token_end(text, equals + 1)
        value_text = text[equals + 1:value_end]
        if value_text.startswith(("'", '"')):
            quote_end = prompt_closing_quote_index(value_text, 0)
            styled_len = len(value_text) if quote_end is None else quote_end + 1
            if styled_len:
                quote_allows_variables = value_text.startswith('"')
                if quote_allows_variables:
                    append_styled_value_fragments(
                        fragments,
                        value_text[:styled_len],
                        string_style or value_style,
                        variable_style,
                    )
                else:
                    fragments.append((string_style or value_style, value_text[:styled_len]))
            if styled_len < len(value_text):
                append_styled_value_fragments(fragments, value_text[styled_len:], value_style, variable_style)
        else:
            append_styled_value_fragments(fragments, value_text, value_style, variable_style)
        index = value_end
    return [fragment for fragment in fragments if fragment[1]]


def append_styled_value_fragments(
    fragments: list[tuple[str, str]],
    text: str,
    value_style: str,
    variable_style: str,
) -> None:
    """Append a value token, letting `$VAR` references override value styling."""
    if not variable_style:
        fragments.append((value_style, text))
        return
    index = 0
    while index < len(text):
        dollar = next_variable_reference_start(text, index)
        if dollar is None:
            fragments.append((value_style, text[index:]))
            break
        fragments.append((value_style, text[index:dollar]))
        end = variable_reference_end(text, dollar + 1)
        fragments.append((variable_style, text[dollar:end]))
        index = end


def append_assignment_key_fragments(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append text before `=`, styling only the assignment key token."""
    if not variable_style:
        append_variable_reference_fragments(fragments, text, variable_style)
        return
    key_start = assignment_key_start(text)
    append_variable_reference_fragments(fragments, text[:key_start], variable_style)
    fragments.append((variable_style, text[key_start:]))


def assignment_key_start(text: str) -> int:
    """Return the token start for the key immediately before an equals sign."""
    index = len(text)
    while index > 0 and not text[index - 1].isspace():
        index -= 1
    return index


def append_variable_reference_fragments(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append plain text while styling `$VAR` references when configured."""
    if not variable_style:
        fragments.append(("", text))
        return
    index = 0
    while index < len(text):
        dollar = next_variable_reference_start(text, index)
        if dollar is None:
            fragments.append(("", text[index:]))
            break
        fragments.append(("", text[index:dollar]))
        end = variable_reference_end(text, dollar + 1)
        fragments.append((variable_style, text[dollar:end]))
        index = end


def next_variable_reference_start(text: str, start: int) -> int | None:
    """Return the next unescaped `$` that begins a variable reference."""
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "$" and index + 1 < len(text) and is_variable_reference_char(text[index + 1]):
            return index
        index += 1
    return None


def variable_reference_end(text: str, start: int) -> int:
    """Return the end of a `$VAR` reference."""
    index = start
    while index < len(text) and is_variable_reference_char(text[index]):
        index += 1
    return index


def is_variable_reference_char(char: str) -> bool:
    """Return whether a character can appear in a Bywaf variable reference."""
    return char.isalnum() or char in {"_", "-", ".", "/"}


def next_unquoted_equals(text: str, start: int) -> int | None:
    """Return the next equals sign outside shell-style quotes."""
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "=":
            return index
    return None


def value_token_end(text: str, start: int) -> int:
    """Return the end of the key=value value token."""
    quote = ""
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char.isspace():
            break
        index += 1
    return index


def prompt_closing_quote_index(text: str, start: int) -> int | None:
    """Return the matching prompt quote index, ignoring escaped quotes."""
    quote = text[start]
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index
    return None


def overlay_secret_fragments(base_fragments, secret_fragments):
    """Let secret-span styling override value/string styling."""
    secret_style_by_index: dict[int, str] = {}
    position = 0
    for style, text in secret_fragments:
        if style:
            for offset in range(len(text)):
                secret_style_by_index[position + offset] = style
        position += len(text)
    if not secret_style_by_index:
        return base_fragments
    merged: list[tuple[str, str]] = []
    position = 0
    for style, text in base_fragments:
        for char in text:
            final_style = secret_style_by_index.get(position, style)
            if merged and merged[-1][0] == final_style:
                merged[-1] = (final_style, f"{merged[-1][1]}{char}")
            else:
                merged.append((final_style, char))
            position += 1
    return merged


def prompt_input_style():
    """Return prompt-toolkit style classes used by secret-input rendering."""
    if Style is None:
        return None
    return Style.from_dict(
        {
            "secret.focused": "bg:ansired #ffffff blink bold",
            "secret.inactive": "bg:#5f0000 #ffffff",
        }
    )


def prompt_fragment_style(style: str) -> str:
    """Translate Bywaf display-style tokens into prompt-toolkit fragments."""
    parts: list[str] = []
    for token in style.split():
        normalized = token.strip().casefold().replace("_", "-")
        if not normalized:
            continue
        if normalized in PROMPT_TOOLKIT_ATTR_NAMES:
            parts.append(normalized)
        elif normalized in {"dim", "blink", "strikethrough"}:
            # These are valid terminal SGR ideas but are not consistently
            # supported in prompt-toolkit style strings, so prompt input ignores
            # them while event rendering still honors them.
            continue
        elif normalized in PROMPT_TOOLKIT_COLOR_NAMES:
            parts.append(PROMPT_TOOLKIT_COLOR_NAMES[normalized])
        elif normalized.startswith("#") and len(normalized) in {4, 7}:
            parts.append(normalized)
        elif normalized.startswith("rgb:"):
            hex_color = rgb_style_to_hex(normalized)
            if hex_color:
                parts.append(hex_color)
    return " ".join(parts)


def rgb_style_to_hex(token: str) -> str | None:
    """Convert `rgb:R,G,B` into a prompt-toolkit hex color."""
    try:
        values = [int(part.strip()) for part in token.removeprefix("rgb:").split(",")]
    except ValueError:
        return None
    if len(values) != 3 or any(value < 0 or value > 255 for value in values):
        return None
    return "#" + "".join(f"{value:02x}" for value in values)


def merge_prompt_key_bindings(*bindings):
    """Merge optional prompt-toolkit key binding sets."""
    present = [binding for binding in bindings if binding is not None]
    if not present:
        return None
    if len(present) == 1 or merge_key_bindings is None:
        return present[0]
    return merge_key_bindings(present)


def secret_input_mode(completer: Completer) -> str:
    """Return the configured secret input method."""
    value = completer.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE)
    mode = str(value or DEFAULT_SECRET_INPUT_MODE).strip().casefold()
    return mode if mode in SECRET_INPUT_MODES else DEFAULT_SECRET_INPUT_MODE


def secret_input_bottom_toolbar(secret_state: PromptSecretInputState):
    """Show secret-block instructions only while the block is focused."""
    if HTML is None or secret_state.focused() is None:
        return None
    return HTML("<b>Secret:</b> type value | <b>Tab</b> accepts | <b>Esc</b> leaves | <b>Enter</b> submits")


def completion_key_bindings(completer: Completer):
    """Return prompt-toolkit keybindings for completion selection."""
    if KeyBindings is None or has_completions is None:
        return None
    bindings = KeyBindings()
    select_key = completion_select_key(completer)

    try:
        register_select_completion_binding(bindings, select_key)
    except ValueError:
        register_select_completion_binding(bindings, DEFAULT_COMPLETION_SELECT_KEY)
    if completion_wasd_selection_enabled(completer):
        register_wasd_completion_bindings(bindings)

    return bindings


def register_select_completion_binding(bindings, select_key: str) -> None:
    """Register the configured completion-selection-mode key.

    Prompt-toolkit normally completes on Tab.  Bywaf also supports an explicit
    "selection mode" key so users can open the menu, move through entries, and
    accept the highlighted value without inserting partial text accidentally.
    """

    @bindings.add(select_key)
    def _select_completion(event) -> None:
        enter_completion_selection_mode(event)

    @bindings.add("enter", filter=has_completions)
    def _accept_completion(event) -> None:
        apply_current_completion(event)

    @bindings.add("tab", filter=has_completions)
    def _accept_completion_with_tab(event) -> None:
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


def register_wasd_completion_bindings(bindings) -> None:
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
    """Accept the highlighted completion, or the first completion if none selected.

    This is called from the prompt-toolkit Enter binding while the completion
    menu is open.  If the UI has not highlighted an item yet, Bywaf treats the
    first visible candidate as the selected candidate.
    """
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


def completion_wasd_selection_enabled(completer: Completer) -> bool:
    """Return whether optional WASD completion navigation is enabled."""
    value = completer.registry.varstore.get(COMPLETION_WASD_SELECTION_VAR, "false")
    return framework_bool(value, default=False)


def completion_select_key(completer: Completer) -> str:
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


def completion_select_key_display(completer: Completer) -> str:
    """Return a human-readable label for the configured selection key."""
    key = completion_select_key(completer)
    if key == "c-space":
        return "Ctrl-Space"
    if key.startswith("c-") and len(key) > 2:
        return f"Ctrl-{key[2:].upper()}"
    return key


def install_readline(completer: Completer) -> None:
    """Install a Completer into Python readline."""
    configure_readline_delimiters()
    readline.set_completer(completer.complete)
    readline.parse_and_bind("tab: complete")


def configure_readline_delimiters() -> None:
    """Keep option dashes and key/value equals signs inside completion tokens.

    Python readline otherwise treats characters like `-` and `=` as token
    boundaries.  Bywaf completions need `--flag`, `key=value`, and scoped
    selector text to remain one token so the completion core sees the same
    shape the command parser will later receive.
    """
    delimiters = readline.get_completer_delims()
    readline.set_completer_delims(delimiters.replace("-", "").replace("=", ""))


def should_print_completion_menu(line: str, candidates: Sequence[str]) -> bool:
    """Use a custom menu for key=value completions so labels stay readable."""
    prefix = completion_prefix(line)
    return (
        len(candidates) > 1
        and "=" in prefix
        and should_display_value_only(prefix, candidates)
    )


def should_display_value_only(prefix: str, candidates: Sequence[str]) -> bool:
    """Return whether completion display should hide a repeated key= prefix."""
    return "=" in prefix and all(candidate.startswith(prefix.split("=", 1)[0] + "=") for candidate in candidates)


def print_completion_menu(line: str, candidates: Sequence[str]) -> None:
    """Print value-only labels for key=value completion candidates."""
    labels = [display_label(candidate) for candidate in candidates]
    print()
    print("  " + "   ".join(labels))
    print(line, end="", flush=True)


def display_label(candidate: str) -> str:
    """Strip key prefixes from key=value candidates for display."""
    if "=" in candidate:
        return candidate.split("=", 1)[1]
    return candidate


def completion_prefix(line: str) -> str:
    """Return the current token prefix from a readline buffer."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    tokens = tokens_after_last_pipe(tokens)
    return "" if line.endswith(" ") else (tokens[-1] if tokens else "")


def completion_results(line: str, candidates: Sequence[str]) -> list[str]:
    """Return readline-formatted completion results.

    Readline cannot separately say "insert this shared prefix first, then show
    these candidates"; it only sees a sequence of candidate strings.  Returning
    the shared prefix as the first candidate gives the normal shell behavior of
    extending as much text as possible before cycling through alternatives.
    """
    common = common_completion_prefix(line, candidates)
    if common:
        return [common, *[format_candidate(candidate) for candidate in candidates]]
    return [format_candidate(candidate) for candidate in candidates]


def common_completion_prefix(line: str, candidates: Sequence[str]) -> str | None:
    """Return a shared candidate prefix that extends the current token."""
    prefix = completion_prefix(line)
    if len(candidates) < 2:
        return None
    common = commonprefix(list(candidates))
    if len(common) > len(prefix):
        return common
    if "=" in prefix:
        key = prefix.split("=", 1)[0] + "="
        if all(candidate.startswith(key) for candidate in candidates):
            suffix_common = commonprefix([candidate[len(key):] for candidate in candidates])
            if len(suffix_common) > len(prefix[len(key):]):
                return key + suffix_common
    return None


def format_candidate(candidate: str) -> str:
    """Append spaces only to complete word-like candidates."""
    if candidate.startswith("--") or candidate.endswith("=") or candidate.endswith("/"):
        return candidate
    return candidate + " "
