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

from ..config.canonical import canonical_config_bytes, config_digest
from ..toml_support import load_data_file


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


def cryptography_signing_primitives():
    """Import optional signing primitives for manifest signature creation."""
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PluginTrustError("warning: cannot sign plugin manifest; install cryptography signing support") from exc
    return serialization, Ed25519PrivateKey


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
def canonical_manifest_bytes(data: dict[str, Any]) -> bytes:
    """Return order-insensitive canonical bytes for plugin manifest signing."""
    return canonical_config_bytes(data)


def plugin_manifest_digest(data: dict[str, Any]) -> str:
    """Return the SHA-256 digest of canonical plugin manifest values."""
    return config_digest(data)


MANIFEST_SIGNATURE_SCHEMA = "bywaf.plugin-manifest-signature.v1"


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


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
