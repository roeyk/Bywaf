"""High-level keyring operations.

Provides key generation, import/export, validation, signing, verification, and
key-name discovery used by runtime commandlets, bundles, and completion.

Used by:
- runtime key and bundle commandlets: manage trust material.
- completion providers: discover named signing and trust keys.
"""

from __future__ import annotations

import base64
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .crypto import (
    crypto_ed25519_private_key,
    load_private_key,
    load_public_key,
    load_public_key_from_private,
    private_key_is_encrypted,
    public_key_fingerprint,
    serialize_private_key,
    serialize_public_key,
)
from .models import SUPPORTED_ALGORITHM, KeyPaths, KeyRecord
from .permissions import write_private_file, write_private_permissions, write_public_file
from .state import signing_state_for_record
from .storage import ensure_key_dirs, key_by_name, key_filename, load_key_records, upsert_key, validate_key_name


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
    # Private material is always written encrypted; the public key and metadata
    # are enough for verification and completion without unlocking the key.
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
        # Preserve already-encrypted material when the caller explicitly does
        # not request re-encryption. Permissions are still normalized.
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
    # When private material exists, verify that it corresponds to the public key
    # rather than trusting the metadata paths.
    if record.private_path is not None:
        private_public = load_public_key_from_private(record.private_path, passphrase)
        if public_key_fingerprint(private_public) != fingerprint:
            raise ValueError(f"private/public key mismatch for key: {name}")
    return signing_state_for_record(record, passphrase)


def sign_bytes(name: str, data: bytes, passphrase: str, paths: KeyPaths | None = None) -> dict[str, str]:
    """Sign bytes with an encrypted private key and return audit-safe metadata."""
    record = key_by_name(name, paths)
    if record.private_path is None:
        raise ValueError(f"key has no private key material: {name}")
    private_key = load_private_key(record.private_path.read_bytes(), passphrase)
    signature = private_key.sign(data)
    return {
        "key": record.name,
        "algorithm": record.algorithm,
        "fingerprint": record.fingerprint,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_bytes(
    name: str,
    data: bytes,
    signature_b64: str,
    paths: KeyPaths | None = None,
) -> bool:
    """Verify a detached signature against a known public key."""
    record = key_by_name(name, paths)
    if record.public_path is None or not record.public_path.exists():
        raise ValueError(f"key has no public key material: {name}")
    public_key = load_public_key(record.public_path.read_bytes())
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, data)
    except Exception:
        return False
    return True


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


def now_iso() -> str:
    """Return a timezone-aware timestamp."""
    return datetime.now(timezone.utc).isoformat()
