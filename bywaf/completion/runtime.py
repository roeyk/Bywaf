"""Runtime completion target inference.

Provides prompt metadata targeting for job, step, and pipeline completions.
Used by CoreCompleter before it asks the database for candidate descriptions.

Used by:
- completion engine: infer which runtime selector is being edited.
- tests: verify selector completion behavior across commands.
"""

from __future__ import annotations

import shlex

from .tokens import tokens_after_last_pipe


def runtime_completion_target(candidate: str, line: str, prefix: str) -> tuple[str | None, str]:
    """Infer whether a completion candidate represents a job, step, or pipeline."""
    for kind in ("job", "step", "pipeline"):
        selector = f"{kind}="
        if candidate.startswith(selector):
            return kind, candidate.removeprefix(selector)
        if prefix.startswith(selector):
            return kind, candidate
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    tokens = tokens_after_last_pipe(tokens)
    # Some runtime commands take a bare id after the action, while others use
    # key=value selectors. Infer the target kind so display metadata can be
    # attached to either completion style.
    if len(tokens) >= 2 and tokens[0] == "pipeline" and tokens[1] in {"attach", "show", "cancel", "end", "kill"}:
        return "pipeline", candidate
    if len(tokens) >= 2 and tokens[0] == "job" and tokens[1] in {"show", "cancel", "end", "kill"}:
        return "job", candidate
    return None, candidate
