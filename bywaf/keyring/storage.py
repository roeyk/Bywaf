"""Keyring metadata storage.

Provides path resolution, TOML metadata load/save, and record lookup/mutation
helpers used by keyring operations and completion providers.

Used by:
- keyring operations: persist and query key metadata.
- runtime key commandlet and completion: list available trust material.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from .models import KEY_NAME_RE, SUPPORTED_ALGORITHM, KeyPaths, KeyRecord
from .permissions import chmod_private_dir


def default_key_paths() -> KeyPaths:
    """Return the default user-local Bywaf keyring layout."""
    configured = os.environ.get("BYWAF_KEY_ROOT")
    root = Path(configured).expanduser() if configured else Path.home() / ".bywaf" / "keys"
    return KeyPaths(
        root=root,
        private_dir=root / "private",
        public_dir=root / "public",
        metadata=root / "keys.toml",
    )


def ensure_key_dirs(paths: KeyPaths | None = None) -> KeyPaths:
    """Create keyring directories with conservative permissions."""
    paths = paths or default_key_paths()
    paths.private_dir.mkdir(parents=True, exist_ok=True)
    paths.public_dir.mkdir(parents=True, exist_ok=True)
    chmod_private_dir(paths.root)
    chmod_private_dir(paths.private_dir)
    paths.public_dir.chmod(0o755)
    return paths


def validate_key_name(name: str) -> str:
    """Validate a key name for metadata and file paths."""
    if not KEY_NAME_RE.fullmatch(name):
        raise ValueError("key names may contain letters, digits, dot, dash, and underscore")
    return name


def key_filename(name: str, suffix: str) -> str:
    """Return a safe filename for one key name."""
    return f"{validate_key_name(name)}{suffix}"


def load_key_records(paths: KeyPaths | None = None) -> list[KeyRecord]:
    """Load key metadata from `keys.toml`."""
    paths = paths or default_key_paths()
    if not paths.metadata.exists():
        return []
    data = tomllib.loads(paths.metadata.read_text(encoding="utf-8"))
    rows = data.get("keys", [])
    if not isinstance(rows, list):
        raise ValueError(f"{paths.metadata} contains invalid keys table")
    records: list[KeyRecord] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        records.append(record_from_dict(row))
    return records


def record_from_dict(row: dict[str, Any]) -> KeyRecord:
    """Create a KeyRecord from metadata."""
    public = optional_path(row.get("public_path"))
    private = optional_path(row.get("private_path"))
    return KeyRecord(
        name=str(row.get("name", "")),
        scope=str(row.get("scope", "user")),
        algorithm=str(row.get("algorithm", SUPPORTED_ALGORITHM)),
        fingerprint=str(row.get("fingerprint", "")),
        public_path=public,
        private_path=private,
        created_at=str(row.get("created_at", "")),
        imported_at=str(row.get("imported_at", "")),
    )


def optional_path(value: object) -> Path | None:
    """Return a Path for non-empty metadata values."""
    if value is None or str(value) == "":
        return None
    return Path(str(value)).expanduser()


def save_key_records(records: list[KeyRecord], paths: KeyPaths | None = None) -> None:
    """Write key metadata as human-readable TOML."""
    paths = ensure_key_dirs(paths)
    lines = ["# Bywaf signing and verification keys", ""]
    for record in sorted(records, key=lambda key: key.name):
        lines.append("[[keys]]")
        lines.append(f'name = "{escape_toml(record.name)}"')
        lines.append(f'scope = "{escape_toml(record.scope)}"')
        lines.append(f'algorithm = "{escape_toml(record.algorithm)}"')
        lines.append(f'fingerprint = "{escape_toml(record.fingerprint)}"')
        if record.public_path is not None:
            lines.append(f'public_path = "{escape_toml(str(record.public_path))}"')
        if record.private_path is not None:
            lines.append(f'private_path = "{escape_toml(str(record.private_path))}"')
        if record.created_at:
            lines.append(f'created_at = "{escape_toml(record.created_at)}"')
        if record.imported_at:
            lines.append(f'imported_at = "{escape_toml(record.imported_at)}"')
        lines.append("")
    paths.metadata.write_text("\n".join(lines), encoding="utf-8")
    try:
        paths.metadata.chmod(0o600)
    except PermissionError:
        pass


def escape_toml(value: str) -> str:
    """Escape a short TOML basic string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def key_by_name(name: str, paths: KeyPaths | None = None) -> KeyRecord:
    """Return one key record or raise a clear error."""
    for record in load_key_records(paths):
        if record.name == name:
            return record
    raise ValueError(f"unknown key: {name}")


def upsert_key(record: KeyRecord, paths: KeyPaths | None = None, *, overwrite: bool = False) -> None:
    """Insert or replace a key metadata record."""
    records = load_key_records(paths)
    existing = [item for item in records if item.name == record.name]
    if existing and not overwrite:
        raise FileExistsError(f"key already exists: {record.name}")
    records = [item for item in records if item.name != record.name]
    records.append(record)
    save_key_records(records, paths)


def remove_key(name: str, paths: KeyPaths | None = None, *, delete_files: bool = False) -> KeyRecord:
    """Remove key metadata and optionally delete referenced files."""
    records = load_key_records(paths)
    removed = [record for record in records if record.name == name]
    if not removed:
        raise ValueError(f"unknown key: {name}")
    keep = [record for record in records if record.name != name]
    save_key_records(keep, paths)
    record = removed[0]
    if delete_files:
        for path in (record.private_path, record.public_path):
            if path is not None:
                path.unlink(missing_ok=True)
    return record
