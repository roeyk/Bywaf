"""Artifact command completion helpers.

Used by: `runtime.artifact.ArtifactCommand` and `SearchCommand` to complete
artifact actions, selectors, runtime entity ids, topics, and filesystem paths.
"""

from __future__ import annotations

from bywaf.plugin import CompletionContext
from bywaf.utils import complete_path

from .common import ARTIFACT_ACTIONS
from .completion import artifact_ids, artifact_topics, job_ids, pipeline_ids, run_ids, serial_ids


def artifact_completion_selectors() -> dict[str, list[str]]:
    """Return selector completions keyed by artifact action."""
    return {
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


def artifact_selector_completion(context: CompletionContext, prefix: str) -> list[str] | None:
    """Complete common artifact selectors and filesystem paths."""
    if prefix.startswith("file="):
        return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
    if prefix.startswith("dir="):
        return [f"dir={candidate}" for candidate in complete_path(prefix.removeprefix("dir="))]
    if prefix.startswith("step="):
        return [f"step={value}" for value in run_ids(context)]
    if prefix.startswith("pipeline="):
        return [f"pipeline={value}" for value in pipeline_ids(context)]
    if prefix.startswith("job="):
        return [f"job={value}" for value in job_ids(context)]
    if prefix.startswith("artifact="):
        return [f"artifact={value}" for value in artifact_ids(context)]
    if prefix.startswith("serial="):
        return [f"serial={value}" for value in serial_ids(context)]
    if prefix.startswith("topic="):
        return [f"topic={value}" for value in artifact_topics(context)]
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
    return ["name=", "filename=", "note=", "content=", "serial=", "--regexp", "artifact=", "step=", "pipeline=", "job=", "since=", "until="]
