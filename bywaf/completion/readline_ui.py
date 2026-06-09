"""Readline completion UI helpers.

This module owns the small readline-facing presentation mechanics that sit
between Bywaf's command-aware candidate generation and the terminal UI.

Used by:
- `completion.facade.Completer`: installs readline callbacks and formats
  completion results.
- `completion.facade.PromptToolkitCompleter`: reuses token-prefix and display
  label helpers for prompt-toolkit candidates.
- completion tests: patch the public `bywaf.completion.readline` module object
  to verify delimiter setup without touching a real interactive shell.
"""

from __future__ import annotations

import readline
import shlex
from collections.abc import Sequence
from os.path import commonprefix

from .tokens import tokens_after_last_pipe


def install_readline(completer) -> None:
    """Install a readline completion callback.

    Called by: `repl.shell.build_input_reader()` when the fallback readline REPL
    is used instead of prompt-toolkit.
    """
    configure_readline_delimiters()
    readline.set_completer(completer.complete)
    readline.parse_and_bind("tab: complete")


def configure_readline_delimiters() -> None:
    """Keep option dashes and key/value equals signs inside completion tokens.

    Called by: `install_readline()` and completion tests. Python readline
    otherwise treats characters like `-` and `=` as token boundaries. Bywaf
    completions need `--flag`, `key=value`, and scoped selector text to remain
    one token so the completion core sees the same shape the parser later sees.
    """
    delimiters = readline.get_completer_delims()
    readline.set_completer_delims(delimiters.replace("-", "").replace("=", ""))


def should_print_completion_menu(line: str, candidates: Sequence[str]) -> bool:
    """Return whether readline should print Bywaf's compact value menu."""
    prefix = completion_prefix(line)
    return (
        len(candidates) > 1
        and "=" in prefix
        and should_display_value_only(prefix, candidates)
    )


def should_display_value_only(prefix: str, candidates: Sequence[str]) -> bool:
    """Return whether display labels should hide a repeated `key=` prefix."""
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
    these candidates"; it only sees a sequence of candidate strings. Returning
    the shared prefix as the first candidate gives normal shell behavior:
    extend as much text as possible before cycling through alternatives.
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
        suffixes = [candidate[len(key):] for candidate in candidates if candidate.startswith(key)]
        if len(suffixes) == len(candidates):
            suffix_common = commonprefix(suffixes)
            if len(suffix_common) > len(prefix[len(key):]):
                return key + suffix_common
    return None


def format_candidate(candidate: str) -> str:
    """Append spaces only to complete word-like candidates."""
    if candidate.startswith("--") or candidate.endswith("=") or candidate.endswith("/"):
        return candidate
    return candidate + " "
