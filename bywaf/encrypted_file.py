"""Small encrypted text-file envelopes.

Provides AES-GCM encryption helpers for framework text resources such as
project config and history files.

Used by:
- REPL persistence helpers: save/load encrypted config and history resources.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

import base64
import getpass
import json
import os
from pathlib import Path

ENCRYPTED_TEXT_SCHEMA = "bywaf.encrypted-text.v1"


def write_encrypted_text(path: Path, plaintext: str, *, label: str) -> None:
    """Write plaintext as an encrypted JSON envelope."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise RuntimeError(f"{label} --encrypt requires the cryptography package") from exc

    passphrase = prompt_new_file_passphrase(path)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    iterations = 600_000
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    envelope = {
        "schema": ENCRYPTED_TEXT_SCHEMA,
        "cipher": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_text_maybe_encrypted(path: Path, *, label: str) -> str:
    """Read plaintext or a Bywaf encrypted text envelope."""
    text = path.read_text(encoding="utf-8")
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(envelope, dict) or envelope.get("schema") != ENCRYPTED_TEXT_SCHEMA:
        return text
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:
        raise RuntimeError(f"encrypted {label} load requires the cryptography package") from exc

    passphrase = getpass.getpass(f"Passphrase for encrypted {label} {path}: ")
    salt = base64.b64decode(str(envelope["salt"]))
    nonce = base64.b64decode(str(envelope["nonce"]))
    ciphertext = base64.b64decode(str(envelope["ciphertext"]))
    iterations = int(envelope["iterations"])
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


def prompt_new_file_passphrase(path: Path) -> str:
    """Prompt twice for a new encrypted resource passphrase."""
    first = getpass.getpass(f"Create passphrase for encrypted file {path}: ")
    second = getpass.getpass("Confirm encrypted file passphrase: ")
    if not first:
        raise ValueError("passphrase cannot be empty")
    if first != second:
        raise ValueError("passphrases did not match")
    return first
