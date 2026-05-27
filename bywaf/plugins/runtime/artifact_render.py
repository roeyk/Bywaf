"""Artifact row and payload rendering helpers.

Contains presentation-neutral formatting for artifact events, listing rows, and
safe export filenames.

Used by:
- runtime.artifact_actions: publish artifact audit events and output rows.
- runtime.bundle: embed artifact metadata in bundles."""

from __future__ import annotations

from bywaf.artifacts import Artifact


def artifact_event_payload(artifact: Artifact) -> dict[str, object]:
    """Return public artifact metadata for audit events."""
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_row_id": artifact.id,
        "name": artifact.name,
        "content_type": artifact.content_type,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "created_at": artifact.created_at,
        "source_path": artifact.source_path,
        "commandlet": artifact.commandlet,
        "job_id": artifact.job_id,
        "pipeline_id": artifact.pipeline_id,
        "command_run_id": artifact.command_run_id,
        "parent_command_run_id": artifact.parent_command_run_id,
        "note": artifact.note,
    }


def format_artifact_row(artifact: Artifact) -> str:
    """Return one timestamp-first artifact listing row."""
    return (
        f"{artifact.created_at} artifact={artifact.id} artifact_id={artifact.artifact_id} "
        f"name={artifact.name} size={artifact.size} sha256={artifact.sha256} "
        f"commandlet={artifact.commandlet or ''} job={artifact.job_id or ''} "
        f"pipeline={artifact.pipeline_id or ''} step={artifact.command_run_id or ''}"
    )


def safe_artifact_filename(artifact: Artifact) -> str:
    """Build a stable export filename for a stored artifact."""
    clean = "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in artifact.name).strip("_")
    return f"{artifact.id}-{clean or artifact.artifact_id}"
