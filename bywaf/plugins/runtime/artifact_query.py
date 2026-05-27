"""Artifact selection and search helpers.

Contains read-only artifact queries, topic filtering, content searches, and
time-window filtering.

Used by:
- runtime.artifact_actions: list, export, verify, and mutate selected artifacts.
- runtime.artifact: implement the standalone `search` commandlet.
- runtime.bundle: filter artifacts for bundle creation."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.audit import parse_compact_time

from .artifact_common import SEARCH_FIELDS
from .artifact_selectors import resolve_artifact_scope, single_value


def select_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> list[Artifact]:
    """Return artifacts selected by id, provenance, serial, or topic."""
    context.audit_capability("artifact.read")
    store = context.artifact_store("artifact")
    artifact_id = single_value(selectors, "artifact")
    if artifact_id is not None:
        artifacts = [store.get(artifact_id)]
        return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))
    serial = single_value(selectors, "serial")
    if serial is not None and serial.startswith("artifact-"):
        artifacts = [store.get(serial)]
        return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))
    scope = resolve_artifact_scope(context, selectors)
    artifacts = store.list(
        job_id=scope.job_id,
        pipeline_id=scope.pipeline_id,
        command_run_id=scope.command_run_id,
    )
    return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))


def search_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> list[Artifact]:
    """Return artifacts matching search/regexp query selectors."""
    context.audit_capability("artifact.read")
    store = context.artifact_store("search")
    artifact_id = single_value(selectors, "artifact")
    if artifact_id is not None:
        artifacts = [store.get(artifact_id)]
    else:
        serial = single_value(selectors, "serial")
        if serial is not None and serial.startswith("artifact-"):
            artifacts = [store.get(serial)]
        else:
            scope = resolve_artifact_scope(context, selectors)
            artifacts = store.list(
                job_id=scope.job_id,
                pipeline_id=scope.pipeline_id,
                command_run_id=scope.command_run_id,
            )
    return filter_artifact_time_window(
        filter_artifact_search(
            artifacts,
            selectors,
            use_regexp="regexp" in selectors,
        ),
        since=single_value(selectors, "since"),
        until=single_value(selectors, "until"),
    )


def filter_artifacts_by_topic(
    context: CommandContext,
    artifacts: list[Artifact],
    topics: list[str],
) -> list[Artifact]:
    """Filter artifacts by main-DB artifact event topics."""
    if not topics:
        return artifacts
    allowed_ids = artifact_ids_for_topics(context, topics)
    return [artifact for artifact in artifacts if artifact.artifact_id in allowed_ids]


def artifact_ids_for_topics(context: CommandContext, topics: list[str]) -> set[str]:
    """Return artifact durable ids referenced by selected artifact topics."""
    ids: set[str] = set()
    events = context.event_store("artifact topic selector")
    for topic in topics:
        for event in events.events_matching(topic=topic, limit=100000):
            artifact_id = event.payload.get("artifact_id")
            if artifact_id:
                ids.add(str(artifact_id))
    return ids


def filter_artifact_search(
    artifacts: list[Artifact],
    selectors: dict[str, list[str]],
    *,
    use_regexp: bool,
) -> list[Artifact]:
    """Filter artifacts by field-specific query selectors."""
    queries = artifact_search_queries(selectors, use_regexp=use_regexp)
    return [artifact for artifact in artifacts if all(query_matches_artifact(query, artifact) for query in queries)]


def filter_artifact_serials(artifacts: list[Artifact], serials: list[str]) -> list[Artifact]:
    """Filter artifacts by exact durable serial selectors."""
    if not serials:
        return artifacts
    wanted = set(serials)
    return [artifact for artifact in artifacts if artifact_serials(artifact) & wanted]


def artifact_serials(artifact: Artifact) -> set[str]:
    """Return durable serials associated with one artifact."""
    return {
        value
        for value in {
            artifact.artifact_id,
            artifact.pipeline_id,
            artifact.command_run_id,
            str(artifact.job_id) if artifact.job_id is not None else None,
        }
        if value
    }


def artifact_search_queries(selectors: dict[str, list[str]], *, use_regexp: bool) -> list[tuple[str, str | re.Pattern[str]]]:
    """Compile search query selectors for artifact metadata/content fields."""
    queries: list[tuple[str, str | re.Pattern[str]]] = []
    for field in SEARCH_FIELDS:
        for value in selectors.get(field, []):
            if use_regexp:
                try:
                    queries.append((field, re.compile(value, re.IGNORECASE)))
                except re.error as exc:
                    raise ValueError(f"invalid search --regexp pattern for {field}=: {exc}") from exc
            else:
                queries.append((field, value.casefold()))
    return queries


def query_matches_artifact(query: tuple[str, str | re.Pattern[str]], artifact: Artifact) -> bool:
    """Return whether one field query matches one artifact."""
    field, expected = query
    value = artifact_field_value(artifact, field)
    if isinstance(expected, re.Pattern):
        return expected.search(value) is not None
    return expected in value.casefold()


def artifact_field_value(artifact: Artifact, field: str) -> str:
    """Return one searchable artifact field as text."""
    fields = {
        "name": artifact.name,
        "filename": Path(artifact.source_path or "").name,
        "note": artifact.note or "",
        "content": artifact_text_content(artifact),
    }
    try:
        return fields[field]
    except KeyError as exc:
        raise ValueError(f"unsupported artifact search field: {field}") from exc


def artifact_text_content(artifact: Artifact) -> str:
    """Decode artifact body for content searches."""
    return artifact.body.decode("utf-8", errors="ignore")


def filter_artifact_time_window(
    artifacts: list[Artifact],
    *,
    since: str | None,
    until: str | None,
) -> list[Artifact]:
    """Filter artifacts by created_at time window."""
    since_time = parse_compact_time(since, until=False) if since is not None else None
    until_time = parse_compact_time(until, until=True) if until is not None else None
    return [
        artifact
        for artifact in artifacts
        if artifact_in_time_window(artifact, since=since_time, until=until_time)
    ]


def artifact_in_time_window(
    artifact: Artifact,
    *,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    """Return whether artifact creation time is within an optional window."""
    created = datetime.fromisoformat(artifact.created_at).replace(tzinfo=None)
    return (since is None or created >= since) and (until is None or created <= until)
