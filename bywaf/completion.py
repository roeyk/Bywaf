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
    from prompt_toolkit.application.current import get_app
    from prompt_toolkit.completion import Completion
    from prompt_toolkit.completion import Completer as PromptToolkitCompleterBase
    from prompt_toolkit.enums import DEFAULT_BUFFER
    from prompt_toolkit.filters import has_completions
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding import merge_key_bindings
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.shortcuts.prompt import CompleteStyle
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    get_app = None
    Completion = None
    PromptToolkitCompleterBase = object
    DEFAULT_BUFFER = "DEFAULT_BUFFER"
    has_completions = None
    HTML = None
    KeyBindings = None
    merge_key_bindings = None
    PromptSession = None
    CompleteStyle = None

from .completion_core import BINARY_OPTION_NAMES
from .completion_core import CoreCompleter
from .completion_core import bundle_candidates
from .completion_core import complete_at_file_prefix
from .completion_core import complete_resource_value
from .completion_core import history_candidates
from .completion_core import is_explicit_path
from .completion_core import key_candidates
from .completion_core import option_is_binary
from .completion_core import positional_index
from .completion_core import preserve_explicit_prefix
from .completion_core import resource_candidates
from .completion_core import runtime_completion_target
from .completion_core import tokens_after_last_pipe
from .completion_core import variable_reference_candidates
from .secret_input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_INPUT_MODE_VAR,
    PromptSecretInputState,
    PromptSecretLexer,
    prompt_secret_key_bindings,
    prompt_secret_output,
    prompt_secret_style,
)

__all__ = [
    "BINARY_OPTION_NAMES",
    "COMPLETION_SELECT_KEY_VAR",
    "COMPLETION_WASD_SELECTION_VAR",
    "DEFAULT_COMPLETION_SELECT_KEY",
    "DEFAULT_SECRET_INPUT_MODE",
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
    "completion_bottom_toolbar",
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
    "resource_candidates",
    "runtime_completion_target",
    "should_display_value_only",
    "should_print_completion_menu",
    "tokens_after_last_pipe",
    "variable_reference_candidates",
]

COMPLETION_SELECT_KEY_VAR = "completion.select-key"
COMPLETION_WASD_SELECTION_VAR = "completion.wasd-selection"
DEFAULT_COMPLETION_SELECT_KEY = "c-space"


class Completer(CoreCompleter):
    """Readline adapter around Bywaf's command-aware completion core."""

    def complete(self, text: str, state: int) -> str | None:
        """Readline callback: return one candidate per requested state."""
        del text
        line = readline.get_line_buffer()
        candidates = self.candidates(line)
        common = common_completion_prefix(line, candidates)
        if state == 0 and common:
            return common
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
    """Prompt-toolkit adapter around Bywaf's command-aware completer."""

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
    """Create a prompt-toolkit session with Bywaf completion behavior."""
    if not prompt_toolkit_available():
        return None
    assert PromptSession is not None
    assert CompleteStyle is not None
    secret_state = PromptSecretInputState()
    completion_bindings = completion_key_bindings(completer)
    secret_bindings = prompt_secret_key_bindings(secret_state, enabled=lambda: secret_input_mode(completer) == "block")
    key_bindings = merge_prompt_key_bindings(completion_bindings, secret_bindings)
    session_kwargs = {
        "lexer": PromptSecretLexer(secret_state),
        "style": prompt_secret_style(),
        "output": prompt_secret_output(secret_state),
    }
    session = PromptSession(
        completer=PromptToolkitCompleter(completer),
        complete_while_typing=False,
        complete_style=CompleteStyle.MULTI_COLUMN,
        reserve_space_for_menu=8,
        bottom_toolbar=lambda: completion_bottom_toolbar(completer),
        key_bindings=key_bindings,
        **{key: value for key, value in session_kwargs.items() if value is not None},
    )
    session.secret_state = secret_state
    return session


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
    return mode if mode in {"block", "getpass"} else DEFAULT_SECRET_INPUT_MODE


def completion_bottom_toolbar(completer: Completer):
    """Display completion menu help only while a menu is active."""
    if get_app is None or HTML is None:
        return ""
    try:
        if get_app().current_buffer.complete_state:
            select_key = completion_select_key_display(completer)
            wasd_hint = " | WASD navigates" if completion_wasd_selection_enabled(completer) else ""
            return HTML(
                f"<b>Completion:</b> <b>{select_key}</b> enters selection | "
                f"arrows move | <b>Enter</b> selects | <b>Esc</b> cancels{wasd_hint}"
            )
    except RuntimeError:
        return ""
    return ""


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
    """Register the configured completion-selection-mode key."""

    @bindings.add(select_key)
    def _select_completion(event) -> None:
        enter_completion_selection_mode(event)

    @bindings.add("enter", filter=has_completions)
    def _accept_completion(event) -> None:
        apply_current_completion(event)

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
    """Keep option dashes and key/value equals signs inside completion tokens."""
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
    """Return readline-formatted completion results."""
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
