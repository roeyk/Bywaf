"""Project archive helpers for REPL project commands.

Provides creation of framework-owned project snapshots containing the active
project database, artifact database, project configuration, and project history.

Used by:
- bywaf.repl.projects: implements `project archive file=<path> [--encrypt]`.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..artifacts import artifact_db_path
from ..projects import ProjectPaths
from ..runner import Runner

ARCHIVE_MANIFEST = "bywaf-archive-manifest.json"
ARCHIVE_SCHEMA = "bywaf.project-archive.v1"
ENCRYPTED_ARCHIVE_SCHEMA = "bywaf.project-archive-encrypted.v1"


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    """One project-owned file included in an archive."""

    path: Path
    arcname: str


def archive_project(runner: Runner, output_path: Path, *, encrypt: bool = False) -> dict[str, Any]:
    """Create a project archive and return manifest metadata."""
    project = runner.project if isinstance(runner.project, ProjectPaths) else None
    if project is None:
        raise ValueError("project archive requires an active project")

    # Checkpoint before collecting files so SQLite WAL state is flushed enough
    # for a portable archive snapshot.
    runner.db.checkpoint()
    members = list(project_archive_members(project))
    if not members:
        raise ValueError(f"project archive found no project files under {project.path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = archive_manifest(project, members, encrypted=encrypt)
    if encrypt:
        write_encrypted_project_archive(output_path, members, manifest)
    else:
        write_project_archive_zip(output_path, members, manifest)

    event = runner.events.publish(
        "project.archived",
        {
            "project": project.name,
            "file": str(output_path),
            "encrypted": encrypt,
            "files": [member.arcname for member in members],
            "manifest": ARCHIVE_MANIFEST,
        },
        "framework",
    )
    return {
        "project": project.name,
        "file": str(output_path),
        "encrypted": encrypt,
        "files": len(members),
        "event_id": event.id,
    }


def project_archive_members(project: ProjectPaths) -> Iterable[ArchiveMember]:
    """Yield existing framework-owned files for a project."""
    # Archive only Bywaf-owned project files. Arbitrary user output belongs in
    # artifacts or external deliverables, not in the project archive by default.
    paths = [
        project.database,
        *sqlite_sidecars(project.database),
        artifact_db_path(project.database),
        *sqlite_sidecars(artifact_db_path(project.database)),
        project.config,
        project.history,
    ]
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not path.exists() or not path.is_file():
            continue
        seen.add(resolved)
        yield ArchiveMember(path, project_relative_archive_name(project, path))


def sqlite_sidecars(path: Path) -> tuple[Path, Path]:
    """Return WAL/SHM sidecar paths for a SQLite database."""
    return (Path(f"{path}-wal"), Path(f"{path}-shm"))


def project_relative_archive_name(project: ProjectPaths, path: Path) -> str:
    """Return a stable archive name relative to the project directory."""
    try:
        return path.relative_to(project.path).as_posix()
    except ValueError:
        return path.name


def archive_manifest(
    project: ProjectPaths,
    members: Iterable[ArchiveMember],
    *,
    encrypted: bool,
) -> dict[str, Any]:
    """Build the archive manifest embedded in every project archive."""
    files = []
    for member in members:
        files.append(
            {
                "path": member.arcname,
                "size": member.path.stat().st_size,
                "sha256": sha256_file(member.path),
            }
        )
    return {
        "schema": ARCHIVE_SCHEMA,
        "bywaf_version": __version__,
        "project": project.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "encrypted": encrypted,
        "files": files,
    }


def write_project_archive_zip(
    output_path: Path,
    members: Iterable[ArchiveMember],
    manifest: dict[str, Any],
) -> None:
    """Write an unencrypted ZIP project archive."""
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in members:
            archive.write(member.path, member.arcname)
        archive.writestr(ARCHIVE_MANIFEST, json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def write_encrypted_project_archive(
    output_path: Path,
    members: Iterable[ArchiveMember],
    manifest: dict[str, Any],
) -> None:
    """Write an encrypted archive envelope containing the ZIP payload."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise RuntimeError("project archive --encrypt requires the cryptography package") from exc

    passphrase = prompt_archive_passphrase(output_path)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    iterations = 600_000
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))

    # Build a normal ZIP first, then encrypt the full byte stream. This keeps
    # encrypted and unencrypted archives sharing one manifest format.
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp:
        temp_path = Path(temp.name)
    try:
        write_project_archive_zip(temp_path, members, manifest)
        ciphertext = AESGCM(key).encrypt(nonce, temp_path.read_bytes(), None)
    finally:
        temp_path.unlink(missing_ok=True)

    envelope = {
        "schema": ENCRYPTED_ARCHIVE_SCHEMA,
        "cipher": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    output_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def prompt_archive_passphrase(path: Path) -> str:
    """Prompt for and confirm a new archive passphrase."""
    first = getpass.getpass(f"Create archive passphrase for {path}: ")
    second = getpass.getpass("Confirm archive passphrase: ")
    if first != second:
        raise ValueError("archive passphrases did not match")
    if not first:
        raise ValueError("archive passphrase cannot be empty")
    return first


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
