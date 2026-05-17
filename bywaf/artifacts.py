"""Encrypted artifact storage linked to the main event audit database."""

from __future__ import annotations

import hashlib
import mimetypes
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db import EventStore, set_sqlcipher_key, sqlcipher


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
    """One decrypted artifact row plus provenance metadata."""

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
        """Rehydrate an artifact from a SQLCipher row."""
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
    """Integrity result for one artifact row."""

    artifact_id: str
    ok: bool
    problems: tuple[str, ...]


class ArtifactStore:
    """SQLCipher-backed artifact body store.

    The main event DB records audit events. This store owns encrypted artifact
    bodies and duplicates enough provenance to stand alone during recovery.
    """

    def __init__(self, path: Path | str, *, passphrase: str):
        if sqlcipher is None:
            raise RuntimeError("artifact storage requires the sqlcipher3-binary package")
        self.path = Path(path)
        self.passphrase = passphrase
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a SQLCipher connection using the main DB passphrase."""
        if sqlcipher is None:
            raise RuntimeError("artifact storage requires the sqlcipher3-binary package")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlcipher.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = sqlcipher.Row
        set_sqlcipher_key(conn, self.passphrase)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the encrypted artifact schema."""
        with self.connect() as conn:
            conn.executescript(ARTIFACT_SCHEMA)

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
        """Store one file as an encrypted artifact and return its row."""
        source_path = path.expanduser()
        data = source_path.read_bytes()
        artifact_id = f"artifact-{uuid.uuid4().hex}"
        content_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
        digest = hashlib.sha256(data).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO artifacts(
                    artifact_id,
                    name,
                    content_type,
                    sha256,
                    size,
                    body,
                    created_at,
                    source_path,
                    commandlet,
                    job_id,
                    pipeline_id,
                    command_run_id,
                    parent_command_run_id,
                    note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    name or source_path.name,
                    content_type,
                    digest,
                    len(data),
                    data,
                    created_at,
                    str(source_path),
                    commandlet,
                    str(job_id) if job_id is not None else None,
                    pipeline_id,
                    command_run_id,
                    parent_command_run_id,
                    note,
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("artifact insert did not return a row id")
            row_id = int(cursor.lastrowid)
        return self.get(row_id)

    def get(self, artifact: int | str) -> Artifact:
        """Return one artifact by numeric id or artifact_id."""
        with self.connect() as conn:
            if isinstance(artifact, int) or str(artifact).isdigit():
                row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (int(artifact),)).fetchone()
            else:
                row = conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (str(artifact),)).fetchone()
        if row is None:
            raise ValueError(f"artifact not found: {artifact}")
        return Artifact.from_row(row)

    def list(
        self,
        *,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Return artifacts matching optional provenance selectors."""
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM artifacts ORDER BY id ASC").fetchall()
        artifacts = [Artifact.from_row(row) for row in rows]
        if job_id is not None:
            artifacts = [artifact for artifact in artifacts if artifact.job_id == str(job_id)]
        if pipeline_id is not None:
            artifacts = [artifact for artifact in artifacts if artifact.pipeline_id == pipeline_id]
        if command_run_id is not None:
            artifacts = [artifact for artifact in artifacts if artifact.command_run_id == command_run_id]
        return artifacts

    def verify(self, artifacts: list[Artifact]) -> list[ArtifactVerification]:
        """Verify artifact body hashes and sizes."""
        results: list[ArtifactVerification] = []
        for artifact in artifacts:
            problems: list[str] = []
            digest = hashlib.sha256(artifact.body).hexdigest()
            if digest != artifact.sha256:
                problems.append("sha256 mismatch")
            if len(artifact.body) != artifact.size:
                problems.append("size mismatch")
            results.append(ArtifactVerification(artifact.artifact_id, not problems, tuple(problems)))
        return results

    def remove(self, artifact: Artifact) -> None:
        """Delete one artifact row from encrypted storage."""
        with self.connect() as conn:
            conn.execute("DELETE FROM artifacts WHERE id = ?", (artifact.id,))

    def replace_file(
        self,
        artifact: Artifact,
        path: Path,
        *,
        name: str | None = None,
        note: str | None = None,
    ) -> Artifact:
        """Replace one artifact body while preserving its stable artifact id."""
        source_path = path.expanduser()
        data = source_path.read_bytes()
        content_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
        digest = hashlib.sha256(data).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE artifacts
                SET name = ?,
                    content_type = ?,
                    sha256 = ?,
                    size = ?,
                    body = ?,
                    created_at = ?,
                    source_path = ?,
                    note = ?
                WHERE id = ?
                """,
                (
                    name if name is not None else artifact.name,
                    content_type,
                    digest,
                    len(data),
                    data,
                    created_at,
                    str(source_path),
                    note if note is not None else artifact.note,
                    artifact.id,
                ),
            )
        return self.get(artifact.id)


def artifact_db_path(main_db_path: Path | str) -> Path:
    """Return the encrypted artifact DB path for a main Bywaf database."""
    path = Path(main_db_path)
    return path.with_name(f"{path.stem}.artifacts.sqlite3")


def artifact_store_for_event_store(db: EventStore) -> ArtifactStore:
    """Open the artifact store using the active encrypted DB passphrase."""
    if db.passphrase is None:
        raise ValueError("artifact storage requires an encrypted main database")
    return ArtifactStore(artifact_db_path(db.path), passphrase=db.passphrase)
