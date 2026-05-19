"""User-local signing key storage and inspection."""
# pyright: reportMissingImports=false

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import stat
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SUPPORTED_ALGORITHM = "ed25519"


@dataclass(frozen=True, slots=True)
class KeyPaths:
    """Filesystem paths for the user-local Bywaf keyring."""

    root: Path
    private_dir: Path
    public_dir: Path
    metadata: Path


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """Metadata for one known signing or verification key."""

    name: str
    scope: str
    algorithm: str
    fingerprint: str
    public_path: Path | None = None
    private_path: Path | None = None
    created_at: str = ""
    imported_at: str = ""

    @property
    def has_private(self) -> bool:
        """Return whether this record points at private key material."""
        return self.private_path is not None

    @property
    def signing_state(self) -> str:
        """Return computed signing state without trusting metadata."""
        return signing_state_for_record(self)


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


def chmod_private_dir(path: Path) -> None:
    """Best-effort chmod for private key directories."""
    try:
        path.chmod(0o700)
    except PermissionError:
        pass


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


def signing_state_for_record(record: KeyRecord, passphrase: str | None = None) -> str:
    """Return computed signing state for a key record.

    This is intentionally derived from the key files, not trusted metadata.
    Encrypted private keys are reported as `locked` until a passphrase is
    supplied; a valid passphrase makes the key `available` for this operation.
    """
    if record.private_path is None:
        return "verify-only"
    if not record.private_path.exists():
        return "invalid"
    try:
        load_public_key_from_private(record.private_path, passphrase)
    except TypeError:
        return "locked"
    except ValueError as exc:
        message = str(exc).lower()
        if passphrase is None and ("password" in message or "encrypted" in message):
            return "locked"
        return "invalid"
    except Exception:
        return "invalid"
    return "available"


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


def generate_key(name: str, passphrase: str, *, scope: str = "user", paths: KeyPaths | None = None) -> KeyRecord:
    """Generate an encrypted Ed25519 keypair."""
    if not passphrase:
        raise ValueError("private key passphrase cannot be empty")
    paths = ensure_key_dirs(paths)
    private_key = crypto_ed25519_private_key()
    private_path = paths.private_dir / key_filename(name, ".pem")
    public_path = paths.public_dir / key_filename(name, ".pub.pem")
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"key files already exist for {name}")
    private_pem = serialize_private_key(private_key, passphrase)
    public_key = private_key.public_key()
    public_pem = serialize_public_key(public_key)
    write_private_file(private_path, private_pem)
    write_public_file(public_path, public_pem)
    record = KeyRecord(
        name=validate_key_name(name),
        scope=scope,
        algorithm=SUPPORTED_ALGORITHM,
        fingerprint=public_key_fingerprint(public_key),
        public_path=public_path,
        private_path=private_path,
        created_at=now_iso(),
    )
    upsert_key(record, paths)
    return record


def import_public_key(
    name: str,
    source: Path,
    *,
    scope: str = "user",
    paths: KeyPaths | None = None,
) -> KeyRecord:
    """Copy an existing public key into the Bywaf keyring."""
    paths = ensure_key_dirs(paths)
    data = source.expanduser().read_bytes()
    public_key = load_public_key(data)
    public_path = paths.public_dir / key_filename(name, ".pub.pem")
    if public_path.exists():
        raise FileExistsError(f"public key file already exists for {name}")
    write_public_file(public_path, serialize_public_key(public_key))
    record = KeyRecord(
        name=validate_key_name(name),
        scope=scope,
        algorithm=SUPPORTED_ALGORITHM,
        fingerprint=public_key_fingerprint(public_key),
        public_path=public_path,
        imported_at=now_iso(),
    )
    upsert_key(record, paths)
    return record


def import_private_key(
    name: str,
    source: Path,
    *,
    scope: str = "user",
    existing_passphrase: str | None = None,
    new_passphrase: str | None = None,
    paths: KeyPaths | None = None,
) -> KeyRecord:
    """Copy or re-encrypt an existing private key into the Bywaf keyring."""
    paths = ensure_key_dirs(paths)
    data = source.expanduser().read_bytes()
    private_key = load_private_key(data, existing_passphrase)
    private_path = paths.private_dir / key_filename(name, ".pem")
    public_path = paths.public_dir / key_filename(name, ".pub.pem")
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"key files already exist for {name}")
    if private_key_is_encrypted(data) and existing_passphrase is not None and new_passphrase is None:
        shutil.copyfile(source.expanduser(), private_path)
        write_private_permissions(private_path)
    else:
        if not new_passphrase:
            raise ValueError("new passphrase is required for plaintext private keys")
        write_private_file(private_path, serialize_private_key(private_key, new_passphrase))
    public_key = private_key.public_key()
    write_public_file(public_path, serialize_public_key(public_key))
    record = KeyRecord(
        name=validate_key_name(name),
        scope=scope,
        algorithm=SUPPORTED_ALGORITHM,
        fingerprint=public_key_fingerprint(public_key),
        public_path=public_path,
        private_path=private_path,
        imported_at=now_iso(),
    )
    upsert_key(record, paths)
    return record


def export_public_key(name: str, destination: Path, paths: KeyPaths | None = None) -> KeyRecord:
    """Write a known public key to a destination file."""
    record = key_by_name(name, paths)
    if record.public_path is None or not record.public_path.exists():
        raise ValueError(f"key has no public key material: {name}")
    destination.expanduser().write_bytes(record.public_path.read_bytes())
    return record


def test_key(name: str, passphrase: str | None = None, paths: KeyPaths | None = None) -> str:
    """Validate one key record and return computed signing state."""
    record = key_by_name(name, paths)
    if record.public_path is None or not record.public_path.exists():
        raise ValueError(f"key has no public key material: {name}")
    public_key = load_public_key(record.public_path.read_bytes())
    fingerprint = public_key_fingerprint(public_key)
    if fingerprint != record.fingerprint:
        raise ValueError(f"fingerprint mismatch for key: {name}")
    if record.private_path is not None:
        private_public = load_public_key_from_private(record.private_path, passphrase)
        if public_key_fingerprint(private_public) != fingerprint:
            raise ValueError(f"private/public key mismatch for key: {name}")
    return signing_state_for_record(record, passphrase)


def signing_key_names(paths: KeyPaths | None = None) -> list[str]:
    """Return keys that can sign after prompting or are already available."""
    return [
        record.name
        for record in load_key_records(paths)
        if record.signing_state in {"available", "locked"}
    ]


def verification_key_names(paths: KeyPaths | None = None) -> list[str]:
    """Return keys that have public verification material."""
    return [
        record.name
        for record in load_key_records(paths)
        if record.public_path is not None and record.public_path.exists()
    ]


def load_public_key_from_private(path: Path, passphrase: str | None):
    """Load the public half from private key material."""
    return load_private_key(path.read_bytes(), passphrase).public_key()


def load_private_key(data: bytes, passphrase: str | None):
    """Load a PEM private key lazily through cryptography."""
    serialization = crypto_serialization()
    password = passphrase.encode("utf-8") if passphrase is not None else None
    return serialization.load_pem_private_key(data, password=password)


def load_public_key(data: bytes):
    """Load a PEM public key lazily through cryptography."""
    return crypto_serialization().load_pem_public_key(data)


def serialize_private_key(private_key, passphrase: str) -> bytes:
    """Serialize an encrypted private key as PKCS8 PEM."""
    serialization = crypto_serialization()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def serialize_public_key(public_key) -> bytes:
    """Serialize a public key as SubjectPublicKeyInfo PEM."""
    serialization = crypto_serialization()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_fingerprint(public_key) -> str:
    """Return an OpenSSH-style SHA256 fingerprint for a public key."""
    serialization = crypto_serialization()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def write_private_file(path: Path, content: bytes) -> None:
    """Write private key material with owner-only permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
    write_private_permissions(path)


def write_private_permissions(path: Path) -> None:
    """Best-effort owner-only permissions for a private key file."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except PermissionError:
        pass


def write_public_file(path: Path, content: bytes) -> None:
    """Write public key material."""
    path.write_bytes(content)
    try:
        path.chmod(0o644)
    except PermissionError:
        pass


def private_key_is_encrypted(data: bytes) -> bool:
    """Return whether PEM private key data declares encryption."""
    return b"ENCRYPTED" in data.splitlines()[0:2]


def now_iso() -> str:
    """Return a timezone-aware timestamp."""
    return datetime.now(timezone.utc).isoformat()


def crypto_ed25519_private_key():
    """Return the cryptography Ed25519 private key class."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - depends on optional dependency.
        raise RuntimeError("key management requires the cryptography package") from exc
    return Ed25519PrivateKey.generate()


def crypto_serialization():
    """Return the cryptography serialization module."""
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover - depends on optional dependency.
        raise RuntimeError("key management requires the cryptography package") from exc
    return serialization
