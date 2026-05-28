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
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.shortcuts.prompt import CompleteStyle
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    Completion = None
    PromptToolkitCompleterBase = object
    PromptSession = None
    CompleteStyle = None

from .constants import BINARY_OPTION_NAMES, option_is_binary
from .engine import CoreCompleter
from .prompt_ui import (
    COMPLETION_SELECT_KEY_VAR,
    COMPLETION_WASD_SELECTION_VAR,
    DEFAULT_COMPLETION_SELECT_KEY,
    BywafPromptLexer,
    apply_current_completion,
    cancel_completion_menu,
    completion_key_bindings,
    completion_select_key,
    completion_select_key_display,
    completion_wasd_selection_enabled,
    enter_completion_selection_mode,
    framework_bool,
    merge_prompt_key_bindings,
    prompt_input_style,
    register_select_completion_binding,
    register_wasd_completion_bindings,
    secret_input_bottom_toolbar,
    secret_input_mode,
)
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
    return PromptSession is not None and CompleteStyle is not None


def build_prompt_session(completer: Completer):
    """Create a prompt-toolkit session with Bywaf completion behavior.

    The REPL uses this when prompt-toolkit is installed.  The session wires
    together completion, secret-input masking, and custom keybindings so the
    shell can offer a richer UI without changing commandlet parsing semantics.
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
        key_bindings=key_bindings,
        **{key: value for key, value in session_kwargs.items() if value is not None},
    )
    # `PromptSession` does not know about Bywaf's secret-input state, but tests
    # and REPL code need access to it.  Attaching it here keeps the state beside
    # the session that owns the corresponding lexer/output objects.
    setattr(session, "secret_state", secret_state)
    return session


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
