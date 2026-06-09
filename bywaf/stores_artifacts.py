"""Artifact store protocol for artifact body and provenance operations."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from .artifacts import Artifact, ArtifactVerification


@runtime_checkable
class ArtifactStoreProtocol(Protocol):
    """Artifact body and provenance storage."""

    path: Path

    @property
    def passphrase(self) -> str | None:
        """Return the in-memory artifact DB passphrase, when active."""
        ...

    def attach_file(
        self,
        path: Path,
        *,
        name: str | None = None,
        note: str | None = None,
        commandlet: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> Artifact:
        """Store one file as an artifact."""
        ...

    def attach_bytes(
        self,
        data: bytes,
        *,
        name: str,
        content_type: str = "application/octet-stream",
        note: str | None = None,
        source_path: str | None = None,
        commandlet: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> Artifact:
        """Store one in-memory artifact body."""
        ...

    def get(self, artifact: int | str) -> Artifact:
        """Return one artifact by local row id or durable artifact id."""
        ...

    def list(
        self,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Return artifacts matching optional provenance selectors."""
        ...

    def verify(self, artifacts: list[Artifact]) -> list[ArtifactVerification]:
        """Verify artifact bodies against stored size and hash metadata."""
        ...

    def remove(self, artifact: Artifact) -> None:
        """Delete one artifact."""
        ...

    def attach_existing(
        self,
        artifact: Artifact,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
        note: str | None = None,
    ) -> Artifact:
        """Update one artifact's provenance attachment."""
        ...

    def replace_file(
        self,
        artifact: Artifact,
        path: Path,
        *,
        name: str | None = None,
        note: str | None = None,
    ) -> Artifact:
        """Replace one artifact body while preserving its durable id."""
        ...
