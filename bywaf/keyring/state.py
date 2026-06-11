"""Computed keyring state helpers.

Provides derived key state without coupling data models to high-level keyring
operations.

Used by:
- keyring models: expose convenience signing state.
- keyring operations and runtime key commandlet: validate key usability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .crypto import public_key_from_private

if TYPE_CHECKING:
    from .models import KeyRecord


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
        public_key_from_private(record.private_path, passphrase)
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
