"""Bundle manifest and content selection helpers."""

from __future__ import annotations

import base64
from typing import Any

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime import audit as audit_plugin
from bywaf.plugins.runtime.artifact import artifact_event_payload
from bywaf.plugins.runtime.bundle.model import Bundle, split_csv


def bundle_manifest(context: CommandContext, bundle: Bundle, *, include_bodies: bool) -> dict[str, Any]:
    """Build a deterministic bundle manifest.

    Called by: show, seal, verify, and export actions.
    """
    items: list[dict[str, Any]] = []
    for item in bundle.items:
        # Resolve each saved selector just-in-time. This keeps create/add cheap
        # while allowing seal/export to operate on the current project DB.
        kind = str(item["kind"])
        selectors = dict(item.get("selectors", {}))
        items.append(resolve_bundle_content(context, kind, selectors, include_bodies=include_bodies))
    return {
        "format": "bywaf.bundle.v1",
        "name": bundle.name,
        "bundle_id": bundle.bundle_id,
        "created_at": bundle.created_at,
        "items": items,
    }


def resolve_bundle_content(
    context: CommandContext,
    kind: str,
    selectors: dict[str, str],
    *,
    include_bodies: bool = False,
) -> dict[str, Any]:
    """Resolve one bundle item into concrete event or artifact records."""
    if kind == "audit":
        events = audit_plugin.selected_events(context, selectors, limit=100000)
        return {
            "kind": kind,
            "selectors": selectors,
            "records": [audit_plugin.event_record(event) for event in events],
        }
    if kind in {"evidence", "reports"}:
        artifacts = selected_artifacts(context, selectors)
        return {
            "kind": kind,
            "selectors": selectors,
            "records": [artifact_record(artifact, include_body=include_bodies) for artifact in artifacts],
        }
    raise ValueError(f"unsupported bundle content kind: {kind}")


def selected_artifacts(context: CommandContext, selectors: dict[str, str]) -> list[Artifact]:
    """Return artifacts selected for a bundle item."""
    store = context.artifact_store("bundle", read_access=True)
    artifacts = store.list(
        job_id=resolve_job_selector(context, selectors.get("job")),
        pipeline_id=resolve_pipeline_selector(context, selectors.get("pipeline")),
        command_run_id=resolve_run_selector(context, selectors.get("step")),
    )
    if "serial" in selectors:
        wanted = selectors["serial"]
        artifacts = [
            artifact
            for artifact in artifacts
            if wanted in {artifact.artifact_id, artifact.pipeline_id, artifact.command_run_id, artifact.job_id}
        ]
    if "commandlet" in selectors:
        wanted = set(split_csv(selectors["commandlet"]))
        artifacts = [artifact for artifact in artifacts if artifact.commandlet in wanted]
    if "since" in selectors or "until" in selectors:
        from bywaf.plugins.runtime.artifact import filter_artifact_time_window

        artifacts = filter_artifact_time_window(
            artifacts,
            since=selectors.get("since"),
            until=selectors.get("until"),
        )
    return artifacts


def resolve_job_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a local job id or durable job serial for bundle selectors."""
    if value is None:
        return None
    if value.isdigit():
        return value
    resolved = context.runtime_store("bundle").job_id_for_serial(value)
    if resolved is None:
        raise ValueError(f"unknown job: {value}")
    return resolved


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve local step id selectors to durable serials."""
    return context.runtime_store("bundle").resolve_run_serial(value) if value is not None else None


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve local pipeline id selectors to durable serials."""
    return context.runtime_store("bundle").resolve_pipeline_serial(value) if value is not None else None


def artifact_record(artifact: Artifact, *, include_body: bool) -> dict[str, Any]:
    """Return bundle-safe artifact metadata, optionally including body bytes."""
    record = artifact_event_payload(artifact)
    if include_body:
        record["body_base64"] = base64.b64encode(artifact.body).decode("ascii")
    return record
