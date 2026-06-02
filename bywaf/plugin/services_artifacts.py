"""Artifact service helpers for plugin command contexts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..artifacts import Artifact, artifact_store_for_event_store
from ..db import EventStore
from ..event import Event

if TYPE_CHECKING:
    from .context import CommandContext


@dataclass(frozen=True, slots=True)
class ContextArtifacts:
    """Framework-mediated artifact API exposed to commandlets.

    Artifacts are stored in the paired artifact database, then mirrored into the
    main event log as `artifact.attached` so reports, bundles, and audit views
    can discover evidence without opening the artifact DB directly.
    """

    context: CommandContext

    def attach_file(
        self,
        path: str | Path,
        *,
        name: str | None = None,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> Artifact:
        """Attach one file to the paired artifact store and audit it."""
        self.context.audit_capability("filesystem.read")
        # Default provenance comes from the current context, but framework
        # commandlets can override it when attaching evidence on behalf of a
        # job, pipeline, or step selected by the operator.
        store = self.context.artifact_store("artifact attach", write_access=True)
        artifact = store.attach_file(
            Path(path),
            name=name,
            note=note,
            commandlet=self.context.source,
            job_id=job_id if job_id is not None else self.context.job_id,
            pipeline_id=pipeline_id if pipeline_id is not None else self.context.pipeline_id,
            command_run_id=command_run_id if command_run_id is not None else self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )
        self.publish_attached(artifact)
        return artifact

    def attach_text(
        self,
        text: str,
        *,
        name: str,
        note: str | None = None,
        content_type: str = "text/plain; charset=utf-8",
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> Artifact:
        """Attach generated text directly to the paired artifact store."""
        store = self.context.artifact_store("artifact attach", write_access=True)
        artifact = store.attach_bytes(
            text.encode("utf-8"),
            name=name,
            content_type=content_type,
            note=note,
            commandlet=self.context.source,
            job_id=job_id if job_id is not None else self.context.job_id,
            pipeline_id=pipeline_id if pipeline_id is not None else self.context.pipeline_id,
            command_run_id=command_run_id if command_run_id is not None else self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )
        self.publish_attached(artifact)
        return artifact

    def attach_files(
        self,
        paths: Iterable[str | Path],
        *,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Attach several files to the same run/job/pipeline provenance."""
        return [
            self.attach_file(
                path,
                note=note,
                job_id=job_id,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
            )
            for path in paths
        ]

    def publish_attached(self, artifact: Artifact) -> Event | None:
        """Record artifact provenance in the main event database."""
        if self.context._db is None:
            return None
        payload = artifact_event_payload(artifact)
        return self.context._db.publish(
            "artifact.attached",
            payload,
            "framework",
            pipeline_id=artifact.pipeline_id,
            command_run_id=artifact.command_run_id,
            parent_command_run_id=artifact.parent_command_run_id,
        )

    def require_event_store(self, label: str) -> EventStore:
        """Return the backing event store without exposing raw DB writes."""
        if self.context._db is None:
            raise ValueError(f"{label} requires an active database")
        return self.context._db


def artifact_event_payload(artifact: Artifact) -> dict[str, Any]:
    """Return the main-DB audit payload for one artifact row."""
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


def attach_generated_artifact(
    db: EventStore,
    data: bytes,
    *,
    name: str,
    content_type: str,
    note: str,
    commandlet: str,
    job_id: int | str | None = None,
    pipeline_id: str | None = None,
    command_run_id: str | None = None,
    parent_command_run_id: str | None = None,
) -> Artifact:
    """Attach generated bytes and mirror the attachment into the event log."""
    store = artifact_store_for_event_store(db)
    artifact = store.attach_bytes(
        data,
        name=name,
        content_type=content_type,
        note=note,
        commandlet=commandlet,
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        parent_command_run_id=parent_command_run_id,
    )
    db.publish(
        "artifact.attached",
        artifact_event_payload(artifact),
        "framework",
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        parent_command_run_id=parent_command_run_id,
    )
    return artifact
