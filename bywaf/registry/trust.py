"""Plugin trust policy, catalog verification, and manifest signatures.

Provides trust-policy dataclasses, catalog signature verification, plugin
manifest signature creation/verification, and shared hash helpers.

Used by:
- registry.core: enforces filesystem plugin trust policy.
- registry.manifest: verifies filesystem plugin manifests before import.
- plugin_check and signer scripts: verify and sign manifests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PluginTrustError(ValueError):
    """Raised when an external plugin is refused by trust policy."""


@dataclass(frozen=True, slots=True)
class PluginTrustPolicy:
    """Operator-selected filesystem plugin trust bypasses.

    This represents the active trust posture for filesystem plugins.
    Constructed by: CLI flags and registry setup.
    Used by: filesystem plugin loading, catalog verification, and manifest
    signature checks.
    """

    allow_unsigned_plugins: bool = False
    allow_unsigned_plugin_manifests: bool = False
    allow_plugin_key_mismatch: bool = False
    allow_missing_plugin_keys: bool = False

    @classmethod
    def developer_bypass(cls) -> "PluginTrustPolicy":
        """Return the broad plugin trust bypass."""
        return cls(
            allow_unsigned_plugins=True,
            allow_unsigned_plugin_manifests=True,
            allow_plugin_key_mismatch=True,
            allow_missing_plugin_keys=True,
        )


@dataclass(frozen=True, slots=True)
class VerifiedPluginCatalog:
    """Runtime plugin catalog accepted by the current trust policy.

    This represents a catalog whose signature policy has already been handled.
    Constructed by: `load_verified_plugin_catalog()`.
    Used by: `enforce_filesystem_plugin_trust()` to bind plugin code and
    manifests to catalog hashes before import.
    """

    path: Path
    plugins: dict[str, dict[str, Any]]
    verified_signature: bool

    def verifies_entry(self, plugin_dir: Path, entry: str) -> bool:
        """Return whether one filesystem plugin package matches the catalog."""
        row = self.plugins.get(entry)
        if row is None:
            return False
        # A trusted catalog binds both executable code and the sidecar manifest.
        # If either file changes after signing, the plugin must be rejected.
        return (
            row.get("module_sha256") == sha256_file(plugin_dir / "plugin.py")
            and row.get("manifest_sha256") == sha256_file(plugin_dir / "bywaf.plugin.toml")
        )


def enforce_filesystem_plugin_trust(
    plugin_dir: Path,
    *,
    entry: str,
    trust_policy: PluginTrustPolicy | None = None,
    catalog: VerifiedPluginCatalog | None = None,
) -> None:
    """Refuse external plugin code unless unsigned plugin loading is allowed.

    Bundled plugins are loaded through package resources and have already gone
    through the reviewed tree. Filesystem plugins are arbitrary local code; the
    current conservative policy is to treat them as unsigned unless a future
    runtime catalog verification step proves otherwise.
    """
    if catalog is not None and catalog.verifies_entry(plugin_dir, entry):
        return
    policy = trust_policy or PluginTrustPolicy()
    if policy.allow_unsigned_plugins:
        return
    raise PluginTrustError(
        f"warning: refusing external plugin {plugin_dir}; "
        "plugin signature is missing or plugin catalog trust is not verified. "
        "Use --allow-unsigned-plugins for unsigned development plugins, or "
        "--allow-untrusted-plugins to bypass all plugin trust checks."
    )

def load_verified_plugin_catalog(
    catalog_path: Path,
    public_key_path: Path | None,
    *,
    trust_policy: PluginTrustPolicy | None = None,
) -> VerifiedPluginCatalog:
    """Load a plugin catalog accepted by the supplied trust policy."""
    policy = trust_policy or PluginTrustPolicy()
    catalog = load_json(catalog_path)
    signature = catalog.get("signature")
    verified_signature = False
    if not isinstance(signature, dict):
        # Unsigned catalogs are allowed only in explicit development bypass
        # modes. Production trust should come from a signed catalog or manifest.
        if not policy.allow_unsigned_plugins:
            raise PluginTrustError(
                f"warning: refusing plugin catalog {catalog_path}; catalog signature is missing. "
                "Use --allow-unsigned-plugins for unsigned development catalogs."
            )
    elif public_key_path is None:
        if not policy.allow_missing_plugin_keys:
            raise PluginTrustError(
                f"warning: refusing plugin catalog {catalog_path}; trusted plugin catalog key is missing. "
                "Use --allow-missing-plugin-keys only for reviewed development catalogs."
            )
    else:
        verify_catalog_signature(catalog, public_key_path, policy)
        verified_signature = True
    plugins = catalog.get("plugins")
    if not isinstance(plugins, list):
        raise PluginTrustError(f"warning: refusing plugin catalog {catalog_path}; plugins must be a list")
    entries: dict[str, dict[str, Any]] = {}
    for row in plugins:
        if not isinstance(row, dict) or not isinstance(row.get("entry"), str):
            raise PluginTrustError(f"warning: refusing plugin catalog {catalog_path}; plugin entries must include entry")
        entries[str(row["entry"])] = row
    return VerifiedPluginCatalog(catalog_path, entries, verified_signature)


def verify_catalog_signature(
    catalog: dict[str, Any],
    public_key_path: Path,
    policy: PluginTrustPolicy,
) -> None:
    """Verify a signed runtime plugin catalog against one public key."""
    signature = catalog.get("signature")
    if not isinstance(signature, dict):
        raise PluginTrustError("warning: refusing plugin catalog; catalog signature is missing")
    if signature.get("algorithm") != "ed25519":
        raise PluginTrustError(f"warning: refusing plugin catalog; unsupported signature algorithm: {signature.get('algorithm')}")
    primitives = cryptography_primitives()
    invalid_signature, serialization, public_cls = primitives
    public_bytes = public_key_path.read_bytes()
    actual_key_hash = hashlib.sha256(public_bytes).hexdigest()
    declared_key_hash = str(signature.get("public_key_sha256") or "")
    if declared_key_hash and declared_key_hash != actual_key_hash and not policy.allow_plugin_key_mismatch:
        # The catalog may declare the signer key fingerprint. When present, it
        # must match the operator-selected key unless a development bypass is on.
        raise PluginTrustError(
            "warning: refusing plugin catalog; signer key fingerprint does not match trusted key. "
            "Use --allow-mismatched-plugin-keys only for reviewed development catalogs."
        )
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public_key, public_cls):
        raise PluginTrustError("warning: refusing plugin catalog; public key is not an Ed25519 key")
    try:
        public_key.verify(base64.b64decode(str(signature["value"])), canonical_catalog_bytes(catalog))
    except invalid_signature as exc:
        raise PluginTrustError("warning: refusing plugin catalog; signature is invalid") from exc


def cryptography_primitives():
    """Import optional signing primitives for runtime catalog verification."""
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PluginTrustError("warning: cannot verify plugin catalog; install cryptography signing support") from exc
    return InvalidSignature, serialization, Ed25519PublicKey


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from disk."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PluginTrustError(f"warning: refusing plugin catalog {path}; expected JSON object")
    return data


def canonical_catalog_bytes(catalog: dict[str, Any]) -> bytes:
    """Return stable bytes used for catalog signature verification."""
    unsigned = {key: value for key, value in catalog.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
