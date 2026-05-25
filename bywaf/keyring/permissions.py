"""Keyring filesystem permission helpers.

Provides conservative directory and file permission handling for private and
public key material.

Used by:
- keyring storage and operations: create secure key directories and files.
- tests: verify private-key material is not written with broad permissions.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def chmod_private_dir(path: Path) -> None:
    """Best-effort chmod for private key directories."""
    try:
        path.chmod(0o700)
    except PermissionError:
        # Some filesystems, especially mounted/shared ones, do not allow chmod.
        # Creation should still proceed, but tests cover normal POSIX behavior.
        pass


def write_private_file(path: Path, content: bytes) -> None:
    """Write private key material with owner-only permissions."""
    # Use os.open so the restrictive mode is applied at creation time, before
    # any process could observe broader default umask permissions.
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
        # Public keys are not secret. chmod failure is acceptable on restrictive
        # or non-POSIX filesystems.
        pass
