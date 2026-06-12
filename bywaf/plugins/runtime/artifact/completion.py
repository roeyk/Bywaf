"""Artifact completion providers.

Keeps database-backed completion queries out of the commandlet class so the
command metadata remains readable.

Used by:
- runtime.artifact: complete artifact actions, selectors, and runtime ids."""

from __future__ import annotations

from bywaf.artifacts import artifact_db_path
from bywaf.plugin import CompletionContext


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion.

    Called by: artifact commandlet completion providers for `step=`.
    """
    try:
        runtime = context.runtime_store("artifact completion")
    except ValueError:
        return []
    return sorted(runtime.run_aliases().values(), key=int)


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion.

    Called by: artifact commandlet completion providers for `pipeline=`.
    """
    try:
        runtime = context.runtime_store("artifact completion")
    except ValueError:
        return []
    return sorted(runtime.pipeline_aliases().values(), key=int)


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion.

    Called by: artifact commandlet completion providers for `job=`.
    """
    try:
        runtime = context.runtime_store("artifact completion")
    except ValueError:
        return []
    return [str(row["id"]) for row in runtime.jobs()]


def artifact_ids(context: CompletionContext) -> list[str]:
    """Return artifact row IDs for completion when the store is unlocked.

    Called by: artifact commandlet completion providers for `artifact=`.
    """
    try:
        events = context.event_store("artifact completion")
    except ValueError:
        return []
    # Artifact bodies live in the sidecar artifact DB. If the main event DB is
    # encrypted and not unlocked, completion should stay quiet rather than
    # prompting from the completion path.
    if events.passphrase is None:
        return []
    if not artifact_db_path(events.path).exists():
        return []
    try:
        store = context.artifact_store("artifact completion")
    except RuntimeError:
        return []
    return [str(artifact.id) for artifact in store.list()]


def serial_ids(context: CompletionContext) -> list[str]:
    """Return durable serials for completion.

    Called by: artifact commandlet completion providers for `serial=`.
    """
    try:
        events = context.event_store("artifact completion")
    except ValueError:
        return []
    return events.serials()


def artifact_topics(context: CompletionContext) -> list[str]:
    """Return artifact event topics for selector completion.

    Called by: artifact commandlet completion providers for `topic=`.
    """
    try:
        events = context.event_store("artifact completion")
    except ValueError:
        return []
    return sorted(topic for topic in events.topics() if topic.startswith("artifact."))
