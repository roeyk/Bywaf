"""Runtime completion target inference.

Provides prompt metadata targeting for job, run, and pipeline completions.
Used by CoreCompleter before it asks the database for candidate descriptions.
"""

from __future__ import annotations

import shlex

from .tokens import tokens_after_last_pipe


def runtime_completion_target(candidate: str, line: str, prefix: str) -> tuple[str | None, str]:
    """Infer whether a completion candidate represents a job, run, or pipeline."""
    for kind in ("job", "run", "pipeline"):
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
    if len(tokens) >= 2 and tokens[0] == "pipeline" and tokens[1] in {"attach", "show", "cancel", "end", "kill"}:
        return "pipeline", candidate
    if len(tokens) >= 2 and tokens[0] == "job" and tokens[1] in {"show", "cancel", "end", "kill"}:
        return "job", candidate
    return None, candidate
