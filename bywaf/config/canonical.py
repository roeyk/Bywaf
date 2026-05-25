"""Canonicalization helpers for signed configuration data.

Provides deterministic conversion of config/TOML-like values into digestable
bytes so comments and formatting do not affect signatures.

Used by:
- manifest and plugin trust tooling: compute stable hashes for signed metadata.
- signature tests: verify canonical data survives ordering and formatting."""


from __future__ import annotations

import hashlib
import json
from typing import Any


DEFAULT_SIGNATURE_KEYS = frozenset({"bywaf_signature"})


def canonical_config_bytes(
    data: dict[str, Any],
    *,
    signature_keys: frozenset[str] = DEFAULT_SIGNATURE_KEYS,
) -> bytes:
    """Return order-insensitive canonical bytes for signing config values."""
    # Signatures should cover semantic config content, not formatting or the
    # signature block itself. Excluding signature keys prevents self-reference.
    unsigned = {key: value for key, value in data.items() if key not in signature_keys}
    return json.dumps(
        canonical_config_value(unsigned),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def config_digest(
    data: dict[str, Any],
    *,
    signature_keys: frozenset[str] = DEFAULT_SIGNATURE_KEYS,
) -> str:
    """Return the SHA-256 digest of canonical config values."""
    return hashlib.sha256(canonical_config_bytes(data, signature_keys=signature_keys)).hexdigest()


def canonical_config_value(value: Any) -> Any:
    """Normalize parsed config values so signatures ignore ordering."""
    if isinstance(value, dict):
        return {str(key): canonical_config_value(item) for key, item in value.items()}
    if isinstance(value, list):
        # Lists in manifests are treated as unordered declarations for signing,
        # so TOML reorderings do not invalidate otherwise equivalent metadata.
        normalized = [canonical_config_value(item) for item in value]
        return sorted(normalized, key=canonical_config_sort_key)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported config value for signing: {type(value).__name__}")


def canonical_config_sort_key(value: Any) -> str:
    """Return a deterministic key for sorting config collections."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
