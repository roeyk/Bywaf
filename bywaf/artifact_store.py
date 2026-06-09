"""Artifact body database implementation.

Used by:
- bywaf.artifacts: public facade that re-exports `ArtifactStore`.
- plugin contexts and runtime artifact commands: store, query, verify, replace,
  and remove evidence files through this store.
"""

from __future__ import annotations

import hashlib
import mimetypes
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .artifact_records import ARTIFACT_SCHEMA, Artifact, ArtifactVerification
from .db import EventStore, new_serial, set_sqlcipher_key, sqlcipher
from .time_format import bywaf_now_iso


class ArtifactStore:
    """Artifact body store paired with a main event DB.

    The main event DB records audit events. This store owns encrypted artifact
    bodies when the main DB is encrypted, otherwise plaintext artifact bodies.
    It duplicates enough provenance to stand alone during recovery.
    """

    def __init__(self, path: Path | str, *, passphrase: str | None = None):
        if passphrase is not None and sqlcipher is None:
            raise RuntimeError("artifact storage requires the sqlcipher3-binary package")
        self.path = Path(path)
        self.passphrase = passphrase
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection using SQLCipher only when the main DB is encrypted."""
        driver: Any = sqlite3
        if self.passphrase is not None:
            if sqlcipher is None:
                raise RuntimeError("artifact storage requires the sqlcipher3-binary package")
            driver = sqlcipher
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = driver.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = driver.Row
        if self.passphrase is not None:
            set_sqlcipher_key(conn, self.passphrase)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the artifact schema."""
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
        """Store one file as an artifact and return its row."""
        source_path = path.expanduser()
        return self.attach_bytes(
            source_path.read_bytes(),
            name=name or source_path.name,
            content_type=mimetypes.guess_type(source_path.name)[0] or "application/octet-stream",
            note=note,
            source_path=str(source_path),
            commandlet=commandlet,
            job_id=job_id,
            pipeline_id=pipeline_id,
            command_run_id=command_run_id,
            parent_command_run_id=parent_command_run_id,
        )

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
        """Store one in-memory artifact body and return its row."""
        artifact_id = self._allocate_artifact_id()
        digest = hashlib.sha256(data).hexdigest()
        created_at = bywaf_now_iso()
        # Store the artifact body and provenance together.  The main event DB
        # gets a separate `artifact.attached` event, but the artifact DB must be
        # useful on its own during archive/recovery workflows.
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
                    name or (Path(source_path).name if source_path else artifact_id),
                    content_type,
                    digest,
                    len(data),
                    data,
                    created_at,
                    source_path,
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

    def _allocate_artifact_id(self) -> str:
        """Return an unused artifact serial, retrying the impossible collision case."""
        with self.connect() as conn:
            for _ in range(5):
                artifact_id = new_serial("artifact")
                row = conn.execute("SELECT 1 FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
                if row is None:
                    return artifact_id
        raise RuntimeError("could not allocate a unique artifact serial")

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
        # Filtering happens in Python because artifact selectors are small and
        # optional.  This keeps the storage query simple while preserving exact
        # provenance matching across job, pipeline, and step scopes.
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
        """Delete one artifact row from storage."""
        with self.connect() as conn:
            conn.execute("DELETE FROM artifacts WHERE id = ?", (artifact.id,))

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
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE artifacts
                SET job_id = ?,
                    pipeline_id = ?,
                    command_run_id = ?,
                    parent_command_run_id = ?,
                    note = ?
                WHERE id = ?
                """,
                (
                    str(job_id) if job_id is not None else None,
                    pipeline_id,
                    command_run_id,
                    parent_command_run_id,
                    note if note is not None else artifact.note,
                    artifact.id,
                ),
            )
        return self.get(artifact.id)

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
        created_at = bywaf_now_iso()
        # Keep `artifact_id` stable so report/bundle references remain valid,
        # but update integrity fields to describe the new body.
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
    """Return the paired artifact DB path for a main Bywaf database."""
    path = Path(main_db_path)
    return path.with_name(f"{path.stem}.artifacts.sqlite3")


def artifact_store_for_event_store(db: EventStore) -> ArtifactStore:
    """Open the paired artifact store using the main DB encryption mode."""
    return ArtifactStore(artifact_db_path(db.path), passphrase=db.passphrase)
