"""Keyring data models and constants.

Provides key metadata records and filesystem layout records used by keyring
storage, operations, and runtime key commandlets.

Used by:
- keyring storage and operations: pass typed key metadata.
- runtime key commandlet: render and validate operator-facing key records.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

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
        from .operations import signing_state_for_record

        return signing_state_for_record(self)
