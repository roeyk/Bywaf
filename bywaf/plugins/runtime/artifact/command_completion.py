"""Artifact command completion helpers.

Used by: `runtime.artifact.ArtifactCommand` and `SearchCommand` to complete
artifact actions, selectors, runtime entity ids, topics, and filesystem paths.
"""

from __future__ import annotations

from collections.abc import Callable

from bywaf.plugin import CompletionContext
from bywaf.utils import complete_path

from .common import ARTIFACT_ACTIONS
from .completion import artifact_ids, artifact_topics, job_ids, pipeline_ids, run_ids, serial_ids

SelectorCompleter = Callable[[CompletionContext, str], list[str]]

ARTIFACT_SELECTOR_COMPLETIONS = {
    "attach": ["artifact=", "serial=", "step=", "pipeline=", "job=", "file=", "name=", "note="],
    "import": ["file=", "name=", "note="],
    "cat": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "limit=", "encoding=", "--page"],
    "replace": ["artifact=", "file=", "name=", "note="],
    "remove": ["artifact=", "serial=", "step=", "pipeline=", "job="],
    "list": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "--page"],
    "show": ["artifact=", "serial="],
    "verify": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic="],
    "export": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "file=", "dir="],
    "search": [
        "name=",
        "filename=",
        "note=",
        "content=",
        "serial=",
        "--regexp",
        "artifact=",
        "step=",
        "pipeline=",
        "job=",
        "since=",
        "until=",
    ],
}
SEARCH_SELECTOR_COMPLETIONS = [
    "name=",
    "filename=",
    "note=",
    "content=",
    "serial=",
    "--regexp",
    "artifact=",
    "step=",
    "pipeline=",
    "job=",
    "since=",
    "until=",
]


def path_candidates(prefix: str, selector: str) -> list[str]:
    """Return filesystem completion candidates for one path selector."""
    return [f"{selector}{candidate}" for candidate in complete_path(prefix.removeprefix(selector))]


def runtime_id_candidates(context: CompletionContext, selector: str, values: Callable[[CompletionContext], list[str]]) -> list[str]:
    """Return runtime id completion candidates for one selector."""
    return [f"{selector}{value}" for value in values(context)]


def file_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `file=` artifact selectors."""
    del context
    return path_candidates(prefix, "file=")


def dir_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `dir=` artifact selectors."""
    del context
    return path_candidates(prefix, "dir=")


def step_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `step=` artifact selectors."""
    del prefix
    return runtime_id_candidates(context, "step=", run_ids)


def pipeline_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `pipeline=` artifact selectors."""
    del prefix
    return runtime_id_candidates(context, "pipeline=", pipeline_ids)


def job_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `job=` artifact selectors."""
    del prefix
    return runtime_id_candidates(context, "job=", job_ids)


def artifact_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `artifact=` selectors."""
    del prefix
    return runtime_id_candidates(context, "artifact=", artifact_ids)


def serial_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `serial=` selectors."""
    del prefix
    return runtime_id_candidates(context, "serial=", serial_ids)


def topic_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete `topic=` selectors."""
    del prefix
    return runtime_id_candidates(context, "topic=", artifact_topics)


# artifact_selector_completion() uses this dispatch table instead of an if/elif
# prefix ladder so each selector's completion source is visible in one place.
ARTIFACT_SELECTOR_DISPATCH: tuple[tuple[str, SelectorCompleter], ...] = (
    ("file=", file_candidates),
    ("dir=", dir_candidates),
    ("step=", step_candidates),
    ("pipeline=", pipeline_candidates),
    ("job=", job_candidates),
    ("artifact=", artifact_candidates),
    ("serial=", serial_candidates),
    ("topic=", topic_candidates),
)


def artifact_completion_selectors() -> dict[str, list[str]]:
    """Return selector completions keyed by artifact action."""
    return {action: list(selectors) for action, selectors in ARTIFACT_SELECTOR_COMPLETIONS.items()}


def artifact_selector_completion(context: CompletionContext, prefix: str) -> list[str] | None:
    """Complete common artifact selectors and filesystem paths."""
    for selector, completer in ARTIFACT_SELECTOR_DISPATCH:
        if prefix.startswith(selector):
            return completer(context, prefix)
    return None


def action_or_selector_candidates(context: CompletionContext, args: list[str], prefix: str) -> list[str]:
    """Complete an artifact action first, then selectors for the chosen action."""
    if not args:
        return list(ARTIFACT_ACTIONS)
    if len(args) == 1 and args[0] not in ARTIFACT_ACTIONS:
        return [action for action in ARTIFACT_ACTIONS if action.startswith(prefix)]
    completion = artifact_selector_completion(context, prefix)
    if completion is not None:
        return completion
    return artifact_completion_selectors().get(args[0], list(ARTIFACT_ACTIONS))


def search_completion_candidates(context: CompletionContext, prefix: str) -> list[str]:
    """Complete standalone `search` selectors and scopes."""
    completion = artifact_selector_completion(context, prefix)
    if completion is not None:
        return completion
    return list(SEARCH_SELECTOR_COMPLETIONS)
