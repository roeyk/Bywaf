"""Completion helpers for the runtime `note` commandlet.

Used by: `note.Note.complete()` to keep commandlet display flow separate from
runtime ID lookup and path completion.
"""

from __future__ import annotations

from bywaf.plugin import CompletionContext
from bywaf.utils import complete_path


def complete_note_args(context: CompletionContext, args: list[str], prefix: str) -> list[str]:
    """Complete note selectors, runtime IDs, and file paths."""
    if prefix.startswith("file="):
        return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
    if prefix.startswith("text="):
        return []
    if prefix.startswith("step="):
        return [f"step={value}" for value in run_ids(context)]
    if prefix.startswith("pipeline="):
        return [f"pipeline={value}" for value in pipeline_ids(context)]
    if prefix.startswith("job="):
        return [f"job={value}" for value in job_ids(context)]
    if not args:
        return ["add", "step=", "pipeline=", "job="]
    if args == ["add"]:
        return ["step=", "pipeline=", "job="]
    return ["file=", "text="] if args and args[0] == "add" else ["file="]


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return sorted(runtime.run_aliases().values(), key=int)


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return sorted(runtime.pipeline_aliases().values(), key=int)


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return [str(row["id"]) for row in runtime.jobs()]
