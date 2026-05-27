"""Artifact completion providers.

Keeps database-backed completion queries out of the commandlet class so the
command metadata remains readable.

Used by:
- runtime.artifact: complete artifact actions, selectors, and runtime ids."""

from __future__ import annotations

from bywaf.artifacts import artifact_db_path, artifact_store_for_event_store
from bywaf.plugin import CompletionContext


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.run_aliases().values(), key=int)


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.pipeline_aliases().values(), key=int)


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    if context.db is None:
        return []
    return [str(row["id"]) for row in context.db.jobs()]


def artifact_ids(context: CompletionContext) -> list[str]:
    """Return artifact row IDs for completion when the store is unlocked."""
    if context.db is None or context.db.passphrase is None:
        return []
    if not artifact_db_path(context.db.path).exists():
        return []
    try:
        store = artifact_store_for_event_store(context.db)
    except RuntimeError:
        return []
    return [str(artifact.id) for artifact in store.list()]


def serial_ids(context: CompletionContext) -> list[str]:
    """Return durable serials for completion."""
    if context.db is None:
        return []
    return context.db.serials()


def artifact_topics(context: CompletionContext) -> list[str]:
    """Return artifact event topics for selector completion."""
    if context.db is None:
        return []
    return sorted(topic for topic in context.db.topics() if topic.startswith("artifact."))
