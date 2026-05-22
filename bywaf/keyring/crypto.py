"""Keyring cryptography adapter.

Provides lazy cryptography imports, PEM serialization, fingerprinting, and
low-level key loading helpers so storage and operations stay independent from
the optional dependency until key management is actually used.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

import base64
import hashlib
from pathlib import Path


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


def private_key_is_encrypted(data: bytes) -> bool:
    """Return whether PEM private key data declares encryption."""
    return b"ENCRYPTED" in data.splitlines()[0:2]


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
