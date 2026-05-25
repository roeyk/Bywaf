"""Public plugin registry facade.

Provides the stable `bywaf.registry` import surface for plugin registry,
manifest parsing, package discovery, filesystem plugin loading, and trust
helpers.

Used by:
- CLI startup and runner construction: load commandlets and trigger providers.
- completion and REPL display: enumerate commandlets, providers, and triggers.
- plugin tooling: parse, verify, and sign plugin manifests."""

from __future__ import annotations

from .config import (
    first_existing,
    load_defaults_file,
    load_module_defaults,
    parse_package_plugin_config,
    parse_plugin_config,
    provider_name,
)
from .core import PluginRegistry
from .loading import (
    load_module_path,
    load_plugin,
    load_plugin_path,
    load_plugins,
    load_plugins_path,
    load_trigger_specs,
)
from .manifest import (
    PluginManifest,
    bool_field,
    enforce_plugin_manifest,
    enforce_trigger_manifest,
    list_field,
    load_filesystem_plugin_package,
    load_filesystem_plugins,
    load_package_manifest,
    optional_string_field,
    parse_plugin_manifest,
    parse_plugin_manifest_data,
    parse_trigger_rows,
    string_field,
    string_list_field,
    table_value,
)
from .trust import (
    MANIFEST_SIGNATURE_SCHEMA,
    PluginManifestTrust,
    PluginTrustError,
    PluginTrustPolicy,
    VerifiedPluginCatalog,
    canonical_catalog_bytes,
    canonical_manifest_bytes,
    cryptography_primitives,
    cryptography_signing_primitives,
    enforce_filesystem_plugin_trust,
    enforce_plugin_manifest_signature,
    load_json,
    load_verified_plugin_catalog,
    plugin_manifest_digest,
    plugin_manifest_signature_block,
    sha256_file,
    string_signature_field,
    verify_catalog_signature,
    verify_plugin_manifest_signature_data,
)

# Public registry facade.  Keeping this list explicit lets callers import the
# supported registry/trust helpers from `bywaf.registry` while internal modules
# stay free to move as the registry implementation is refined.
__all__ = [
    "MANIFEST_SIGNATURE_SCHEMA",
    "PluginManifest",
    "PluginManifestTrust",
    "PluginRegistry",
    "PluginTrustError",
    "PluginTrustPolicy",
    "VerifiedPluginCatalog",
    "bool_field",
    "canonical_catalog_bytes",
    "canonical_manifest_bytes",
    "cryptography_primitives",
    "cryptography_signing_primitives",
    "enforce_filesystem_plugin_trust",
    "enforce_plugin_manifest",
    "enforce_plugin_manifest_signature",
    "enforce_trigger_manifest",
    "first_existing",
    "list_field",
    "load_defaults_file",
    "load_filesystem_plugin_package",
    "load_filesystem_plugins",
    "load_json",
    "load_module_defaults",
    "load_module_path",
    "load_package_manifest",
    "load_plugin",
    "load_plugin_path",
    "load_plugins",
    "load_plugins_path",
    "load_trigger_specs",
    "load_verified_plugin_catalog",
    "optional_string_field",
    "parse_package_plugin_config",
    "parse_plugin_config",
    "parse_plugin_manifest",
    "parse_plugin_manifest_data",
    "parse_trigger_rows",
    "plugin_manifest_digest",
    "plugin_manifest_signature_block",
    "provider_name",
    "sha256_file",
    "string_field",
    "string_list_field",
    "string_signature_field",
    "table_value",
    "verify_catalog_signature",
    "verify_plugin_manifest_signature_data",
]
