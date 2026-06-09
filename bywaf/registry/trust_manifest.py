"""Plugin manifest signature creation and verification.

Used by:
- `registry.manifest`: enforces signed filesystem sidecars before plugin import.
- `scripts/plugin_manifest_sign.py`: creates manifest signature blocks.
- `plugin_check`: verifies submitted manifests when requested.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config.canonical import canonical_config_bytes, config_digest
from ..toml_support import load_data_file
from .trust import PluginTrustError, PluginTrustPolicy, cryptography_primitives


@dataclass(frozen=True, slots=True)
class PluginManifestTrust:
    """Manifest signature verification inputs for filesystem plugins.

    This represents trust inputs needed to verify one plugin sidecar.
    Constructed by: registry and plugin-check paths from operator/catalog
    settings.
    Used by: manifest verification before filesystem plugin import.
    """

    public_key_path: Path | None = None
    catalog_verified: bool = False


MANIFEST_SIGNATURE_SCHEMA = "bywaf.plugin-manifest-signature.v1"


def canonical_manifest_bytes(data: dict[str, Any]) -> bytes:
    """Return order-insensitive canonical bytes for plugin manifest signing."""
    return canonical_config_bytes(data)


def plugin_manifest_digest(data: dict[str, Any]) -> str:
    """Return the SHA-256 digest of canonical plugin manifest values."""
    return config_digest(data)


def enforce_plugin_manifest_signature(
    manifest_path: Path,
    *,
    trust_policy: PluginTrustPolicy | None = None,
    manifest_trust: PluginManifestTrust | None = None,
) -> None:
    """Refuse unsigned or invalid filesystem plugin manifests unless explicitly allowed."""
    policy = trust_policy or PluginTrustPolicy()
    trust = manifest_trust or PluginManifestTrust()
    if trust.catalog_verified:
        # Catalog verification already covered the manifest hash, so avoid
        # requiring every cataloged plugin to also carry an inline signature.
        return
    if policy.allow_unsigned_plugin_manifests:
        return
    data = load_data_file(manifest_path)
    verify_plugin_manifest_signature_data(data, trust.public_key_path, manifest_path)


def verify_plugin_manifest_signature_data(data: dict[str, Any], public_key_path: Path | None, source: Path) -> None:
    """Verify one parsed manifest signature block against a trusted public key."""
    signature = data.get("bywaf_signature")
    if not isinstance(signature, dict):
        raise PluginTrustError(
            f"warning: refusing plugin manifest {source}; manifest signature is missing. "
            "Use --allow-unsigned-plugin-manifests only for reviewed development manifests."
        )
    if public_key_path is None:
        raise PluginTrustError(
            f"warning: refusing plugin manifest {source}; trusted plugin manifest key is missing. "
            "Use --plugin-manifest-key or --allow-unsigned-plugin-manifests."
        )
    if signature.get("schema") != MANIFEST_SIGNATURE_SCHEMA:
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; unsupported manifest signature schema")
    if signature.get("algorithm") != "ed25519":
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; unsupported manifest signature algorithm")
    if signature.get("digest_algorithm") != "sha256":
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; unsupported manifest digest algorithm")
    digest = plugin_manifest_digest(data)
    if signature.get("digest") != digest:
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; manifest digest mismatch")
    primitives = cryptography_primitives()
    invalid_signature, serialization, public_cls = primitives
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public_key, public_cls):
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; public key is not an Ed25519 key")
    try:
        public_key.verify(base64.b64decode(string_signature_field(signature, "value", source)), digest.encode("ascii"))
    except invalid_signature as exc:
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; manifest signature is invalid") from exc


def string_signature_field(data: dict[str, Any], key: str, source: Path) -> str:
    """Return a required string from a signature block."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; signature {key} must be a string")
    return value


def plugin_manifest_signature_block(data: dict[str, Any], private_key_path: Path, passphrase: str | None = None) -> dict[str, str]:
    """Return a signature block for one parsed plugin manifest."""
    primitives = cryptography_signing_primitives()
    _serialization, private_cls = primitives
    private_key = _serialization.load_pem_private_key(private_key_path.read_bytes(), password=passphrase.encode("utf-8") if passphrase else None)
    if not isinstance(private_key, private_cls):
        raise PluginTrustError("warning: private key is not an Ed25519 key")
    digest = plugin_manifest_digest(data)
    signature = private_key.sign(digest.encode("ascii"))
    return {
        "schema": MANIFEST_SIGNATURE_SCHEMA,
        "algorithm": "ed25519",
        "digest_algorithm": "sha256",
        "digest": digest,
        "value": base64.b64encode(signature).decode("ascii"),
    }


def cryptography_signing_primitives():
    """Import optional signing primitives for manifest signature creation."""
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PluginTrustError("warning: cannot sign plugin manifest; install cryptography signing support") from exc
    return serialization, Ed25519PrivateKey
