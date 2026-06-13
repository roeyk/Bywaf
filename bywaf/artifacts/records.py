"""Artifact storage record types and schema.

Used by:
- `bywaf.artifacts.store.ArtifactStore`: persists and rehydrates artifact rows.
- runtime artifact commands and plugin services: consume typed `Artifact`
  records through the public `bywaf.artifacts` package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


ARTIFACT_SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    content_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    body BLOB NOT NULL,
    created_at TEXT NOT NULL,
    source_path TEXT,
    commandlet TEXT,
    job_id TEXT,
    pipeline_id TEXT,
    command_run_id TEXT,
    parent_command_run_id TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_scope
ON artifacts(job_id, pipeline_id, command_run_id);
"""


@dataclass(frozen=True, slots=True)
class Artifact:
    """One artifact row plus provenance metadata.

    Represents: a stored artifact body and its runtime provenance.
    Constructed by: `Artifact.from_row()` after `ArtifactStore` queries.
    Consumed by: runtime artifact commands, bundle/export paths, reports, audit
    views, and plugin services that attach or inspect evidence.
    """

    id: int
    artifact_id: str
    name: str
    content_type: str
    sha256: str
    size: int
    body: bytes
    created_at: str
    source_path: str | None
    commandlet: str | None
    job_id: str | None
    pipeline_id: str | None
    command_run_id: str | None
    parent_command_run_id: str | None
    note: str | None

    @classmethod
    def from_row(cls, row: Any) -> "Artifact":
        """Rehydrate an artifact from a database row.

        Called by: artifact-store query methods before returning typed artifact
        records to runtime artifact, bundle, export, and report paths.
        """
        return cls(
            id=int(row["id"]),
            artifact_id=str(row["artifact_id"]),
            name=str(row["name"]),
            content_type=str(row["content_type"]),
            sha256=str(row["sha256"]),
            size=int(row["size"]),
            body=bytes(row["body"]),
            created_at=str(row["created_at"]),
            source_path=row["source_path"],
            commandlet=row["commandlet"],
            job_id=row["job_id"],
            pipeline_id=row["pipeline_id"],
            command_run_id=row["command_run_id"],
            parent_command_run_id=row["parent_command_run_id"],
            note=row["note"],
        )


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    """Integrity result for one artifact row.

    Represents: whether stored metadata still matches the artifact body.
    Constructed by: `ArtifactStore.verify()` after comparing hashes and sizes.
    Consumed by: runtime artifact and bundle commands that show integrity
    status and problems to operators.
    """

    artifact_id: str
    ok: bool
    problems: tuple[str, ...]
