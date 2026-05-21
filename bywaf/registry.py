"""Plugin discovery."""

from __future__ import annotations

import importlib
import importlib.util
import base64
import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

from .config_canonical import canonical_config_bytes, config_digest
from .plugin import Commandlet
from .specs import TriggerSpec
from .secrets import InMemorySecretStore
from .toml_support import load_data_file
from .varstore import VarStore


class PluginTrustError(ValueError):
    """Raised when an external plugin is refused by trust policy."""


@dataclass(frozen=True, slots=True)
class PluginTrustPolicy:
    """Operator-selected filesystem plugin trust bypasses."""

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
    """Runtime plugin catalog accepted by the current trust policy."""

    path: Path
    plugins: dict[str, dict[str, Any]]
    verified_signature: bool

    def verifies_entry(self, plugin_dir: Path, entry: str) -> bool:
        """Return whether one filesystem plugin package matches the catalog."""
        row = self.plugins.get(entry)
        if row is None:
            return False
        return (
            row.get("module_sha256") == sha256_file(plugin_dir / "plugin.py")
            and row.get("manifest_sha256") == sha256_file(plugin_dir / "bywaf.plugin.toml")
        )


@dataclass(frozen=True, slots=True)
class PluginManifestTrust:
    """Manifest signature verification inputs for filesystem plugins."""

    public_key_path: Path | None = None
    catalog_verified: bool = False


@dataclass(slots=True)
class PluginRegistry:
    """Loaded commandlets plus their provider grouping and shared variables."""

    plugins: dict[str, Commandlet]
    varstore: VarStore = field(default_factory=VarStore)
    providers: dict[str, list[str]] = field(default_factory=dict)
    secrets: InMemorySecretStore = field(default_factory=InMemorySecretStore)
    triggers: list[TriggerSpec] = field(default_factory=list)
    trigger_providers: dict[int, str] = field(default_factory=dict)

    @classmethod
    def discover(
        cls,
        package_name: str = "bywaf.plugins",
        *,
        config_name: str = "plugins.toml",
        varstore: VarStore | None = None,
    ) -> "PluginRegistry":
        """Load bundled plugins from a package-level config file."""
        entries = parse_package_plugin_config(package_name, config_name)
        store = varstore or VarStore()
        registry = cls({}, store)
        for entry in entries:
            registry.load_package_entry(package_name, entry)
        return registry

    @classmethod
    def from_config(
        cls,
        plugin_root: Path | str,
        config_file: Path | str,
        *,
        varstore: VarStore | None = None,
        forced: bool = False,
        trust_policy: PluginTrustPolicy | None = None,
        catalog: VerifiedPluginCatalog | None = None,
    ) -> "PluginRegistry":
        """Load plugins from an explicit filesystem config file."""
        registry = cls({}, varstore or VarStore())
        policy = PluginTrustPolicy.developer_bypass() if forced else trust_policy
        for entry in parse_plugin_config(Path(config_file)):
            registry.load_filesystem_entry(Path(plugin_root), entry, trust_policy=policy, catalog=catalog)
        return registry

    def load_filesystem_entry(
        self,
        plugin_root: Path,
        entry: str,
        *,
        forced: bool = False,
        trust_policy: PluginTrustPolicy | None = None,
        catalog: VerifiedPluginCatalog | None = None,
        manifest_key: Path | None = None,
    ) -> Commandlet:
        """Load commandlets from `<plugin_root>/<entry>`, enforcing its manifest."""
        plugin_dir = plugin_root / entry
        policy = PluginTrustPolicy.developer_bypass() if forced else trust_policy
        enforce_filesystem_plugin_trust(plugin_dir, entry=entry, trust_policy=policy, catalog=catalog)
        manifest_trust = PluginManifestTrust(
            public_key_path=manifest_key,
            catalog_verified=catalog is not None and catalog.verifies_entry(plugin_dir, entry),
        )
        plugins, triggers = load_filesystem_plugin_package(plugin_dir, trust_policy=policy, manifest_trust=manifest_trust)
        for plugin in plugins:
            self.plugins[plugin.spec.name] = plugin
            self.providers.setdefault(provider_name(entry), []).append(plugin.spec.name)
            load_defaults_file(plugin_dir, plugin, self.varstore)
        self.add_triggers(entry, triggers)
        return plugins[0]

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name."""
        manifest = load_package_manifest(package_name, entry)
        module = importlib.import_module(f"{package_name}.{entry}")
        plugins = load_plugins(module)
        triggers = load_trigger_specs(module)
        if manifest is not None:
            manifest_path = Path(f"{package_name}.{entry}.plugin.toml")
            plugins = enforce_plugin_manifest(manifest, plugins, manifest_path)
            triggers = enforce_trigger_manifest(manifest, triggers, manifest_path)
        elif triggers:
            raise ValueError(f"{package_name}.{entry} exposes undeclared triggers without a plugin manifest")
        for plugin in plugins:
            self.plugins[plugin.spec.name] = plugin
            self.providers.setdefault(provider_name(entry), []).append(plugin.spec.name)
            load_module_defaults(module, plugin, self.varstore)
        self.add_triggers(entry, triggers)
        return plugins[0]

    def get(self, name: str) -> Commandlet:
        """Return a commandlet by user-facing command name."""
        try:
            return self.plugins[name]
        except KeyError as exc:
            raise KeyError(f"unknown commandlet: {name}") from exc

    def names(self) -> list[str]:
        """Return commandlet names for command completion."""
        return sorted(self.plugins)

    def provider_names(self) -> list[str]:
        """Return provider names for the `plugins` command."""
        return sorted(self.providers)

    def grouped_names(self) -> dict[str, list[str]]:
        """Return commandlets grouped by provider for the `cmds` command."""
        return {provider: sorted(set(names)) for provider, names in sorted(self.providers.items())}

    def add_triggers(self, provider: str, triggers: tuple[TriggerSpec, ...] | list[TriggerSpec]) -> None:
        """Register provider-local trigger specs with framework identity metadata."""
        for trigger in triggers:
            self.triggers.append(trigger)
            self.trigger_providers[id(trigger)] = provider

    def trigger_provider(self, trigger: TriggerSpec) -> str | None:
        """Return the provider identity for one registered trigger."""
        return self.trigger_providers.get(id(trigger))

    def trigger_id(self, trigger: TriggerSpec) -> str:
        """Return the durable framework identity for a provider-owned trigger."""
        provider = self.trigger_provider(trigger)
        if provider is None:
            return trigger.name
        return f"{provider}.{trigger.name}"


def load_plugin(module: ModuleType) -> Commandlet:
    """Instantiate a plugin module via its required `plugin()` factory."""
    return load_plugins(module)[0]


def load_plugins(module: ModuleType) -> tuple[Commandlet, ...]:
    """Instantiate one or more commandlets from a plugin module."""
    multi_factory = getattr(module, "plugins", None)
    if multi_factory is not None:
        plugins = tuple(multi_factory())
        if not plugins:
            raise ValueError(f"{module.__name__}.plugins() returned no commandlets")
        return plugins
    factory = getattr(module, "plugin", None)
    if factory is None:
        raise AttributeError(f"{module.__name__} does not define plugin()")
    return (factory(),)


def load_trigger_specs(module: ModuleType) -> tuple[TriggerSpec, ...]:
    """Instantiate optional trigger specs from a provider plugin module."""
    factory = getattr(module, "triggers", None)
    if factory is None:
        return ()
    specs = tuple(factory())
    for spec in specs:
        if not isinstance(spec, TriggerSpec):
            raise TypeError(f"{module.__name__}.triggers() must return TriggerSpec objects")
    return specs


def load_plugin_path(path: Path) -> Commandlet:
    """Load an external plugin module from a concrete Python file path."""
    return load_plugins_path(path)[0]


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


def load_plugins_path(path: Path) -> tuple[Commandlet, ...]:
    """Load external commandlets from a concrete Python file path."""
    return load_plugins(load_module_path(path))


def load_module_path(path: Path) -> ModuleType:
    """Load an external Python module from a concrete file path."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    module_name = f"bywaf_external_{path.parent.name}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Pre-import metadata that controls filesystem plugin exposure."""

    commandlets: frozenset[str]
    triggers: tuple[TriggerSpec, ...] = ()
    commandlet_capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    library_backed: bool = False
    process_wrapped: bool = False
    service: bool = False
    native: bool = False
    roles: tuple[str, ...] = ()


def load_filesystem_plugins(plugin_dir: Path) -> tuple[Commandlet, ...]:
    """Load a filesystem plugin package and enforce its required manifest."""
    return load_filesystem_plugin_package(plugin_dir)[0]


def load_filesystem_plugin_package(
    plugin_dir: Path,
    *,
    trust_policy: PluginTrustPolicy | None = None,
    manifest_trust: PluginManifestTrust | None = None,
) -> tuple[tuple[Commandlet, ...], tuple[TriggerSpec, ...]]:
    """Load filesystem commandlets and provider-owned trigger specs."""
    manifest_path = plugin_dir / "bywaf.plugin.toml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"{manifest_path} not found")
    enforce_plugin_manifest_signature(manifest_path, trust_policy=trust_policy, manifest_trust=manifest_trust)
    manifest = parse_plugin_manifest(manifest_path)
    module = load_module_path(plugin_dir / "plugin.py")
    plugins = enforce_plugin_manifest(manifest, load_plugins(module), manifest_path)
    triggers = enforce_trigger_manifest(manifest, load_trigger_specs(module), manifest_path)
    return plugins, triggers


def parse_plugin_manifest(path: Path) -> PluginManifest:
    """Parse and validate a filesystem plugin manifest."""
    return parse_plugin_manifest_data(load_data_file(path), str(path))


def parse_plugin_manifest_data(data: dict[str, Any], source: str) -> PluginManifest:
    """Parse and validate plugin manifest data from TOML."""
    plugin_data = table_value(data, "plugin", source)
    commandlet_rows = data.get("commandlets")
    if not isinstance(commandlet_rows, list) or not commandlet_rows:
        raise ValueError(f"{source} must declare at least one [[commandlets]] entry")
    commandlets: set[str] = set()
    commandlet_capabilities: dict[str, tuple[str, ...]] = {}
    commandlet_secret_options: dict[str, tuple[str, ...]] = {}
    for index, row in enumerate(commandlet_rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} commandlets entry {index} must be a table")
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{source} commandlets entry {index} requires name")
        commandlets.add(name)
        context = f"commandlets entry {index}"
        commandlet_capabilities[name] = string_list_field(row, "capabilities", source, context)
        commandlet_secret_options[name] = string_list_field(row, "secret_options", source, context)
    library_backed = bool_field(plugin_data, "library_backed", source, "plugin")
    process_wrapped = bool_field(plugin_data, "process_wrapped", source, "plugin")
    service = bool_field(plugin_data, "service", source, "plugin")
    native = bool_field(plugin_data, "native", source, "plugin")
    if native and (library_backed or process_wrapped):
        raise ValueError(f"{source} native=true conflicts with library_backed or process_wrapped")
    roles = string_list_field(plugin_data, "roles", source, "plugin")
    triggers = parse_trigger_rows(data.get("triggers", []), source)
    return PluginManifest(
        commandlets=frozenset(commandlets),
        triggers=triggers,
        commandlet_capabilities=commandlet_capabilities,
        commandlet_secret_options=commandlet_secret_options,
        library_backed=library_backed,
        process_wrapped=process_wrapped,
        service=service,
        native=native or not (library_backed or process_wrapped),
        roles=roles,
    )


def parse_trigger_rows(value: Any, source: str) -> tuple[TriggerSpec, ...]:
    """Parse optional [[triggers]] manifest entries."""
    if value in (None, []):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} triggers must be a list")
    triggers: list[TriggerSpec] = []
    names: set[str] = set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} triggers entry {index} must be a table")
        name = string_field(row, "name", source, f"triggers entry {index}")
        if name in names:
            raise ValueError(f"{source} duplicate trigger: {name}")
        names.add(name)
        topic = string_field(row, "topic", source, f"triggers entry {index}")
        action_command = string_field(row, "action_command", source, f"triggers entry {index}")
        action_mode = optional_string_field(row, "action_mode", source, f"triggers entry {index}", default="service")
        assert action_mode is not None
        if action_mode not in {"foreground", "background", "service"}:
            raise ValueError(f"{source} triggers entry {index} action_mode must be foreground, background, or service")
        payload_equals = row.get("payload_equals", {})
        if not isinstance(payload_equals, dict):
            raise ValueError(f"{source} triggers entry {index} payload_equals must be a table")
        for key, item in payload_equals.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{source} triggers entry {index} payload_equals keys must be strings")
            if not isinstance(item, str):
                raise ValueError(f"{source} triggers entry {index} payload_equals values must be strings")
        suppress_self_trigger = row.get("suppress_self_trigger", True)
        if not isinstance(suppress_self_trigger, bool):
            raise ValueError(f"{source} triggers entry {index} suppress_self_trigger must be true or false")
        description = optional_string_field(row, "description", source, f"triggers entry {index}", default="")
        capability = optional_string_field(row, "capability", source, f"triggers entry {index}")
        triggers.append(
            TriggerSpec(
                name=name,
                topic=topic,
                action_command=action_command,
                description=description or "",
                action_mode=action_mode,
                capability=capability,
                payload_equals=tuple(sorted(payload_equals.items())),
                active_job=bool_field(row, "active_job", source, f"triggers entry {index}"),
                exclude_commandlets=string_list_field(row, "exclude_commandlets", source, f"triggers entry {index}"),
                suppress_self_trigger=suppress_self_trigger,
            )
        )
    return tuple(triggers)


def string_field(data: dict[str, Any], key: str, source: str, context: str) -> str:
    """Return a required string field."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source} {context} requires {key}")
    return value


def optional_string_field(
    data: dict[str, Any],
    key: str,
    source: str,
    context: str,
    *,
    default: str | None = None,
) -> str | None:
    """Return an optional string manifest field."""
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def string_signature_field(data: dict[str, Any], key: str, source: Path) -> str:
    """Return a required string from a signature block."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise PluginTrustError(f"warning: refusing plugin manifest {source}; signature {key} must be a string")
    return value


def enforce_plugin_manifest(
    manifest: PluginManifest,
    plugins: tuple[Commandlet, ...],
    path: Path,
) -> tuple[Commandlet, ...]:
    """Return only manifest-declared commandlets and reject missing declarations."""
    by_name = {plugin.spec.name: plugin for plugin in plugins}
    missing = sorted(manifest.commandlets.difference(by_name))
    if missing:
        raise ValueError(f"{path} declares missing commandlets: {', '.join(missing)}")
    for name in sorted(manifest.commandlets):
        manifest_caps = set(manifest.commandlet_capabilities.get(name, ()))
        code_caps = set(by_name[name].spec.capabilities)
        if manifest_caps != code_caps:
            missing_caps = sorted(code_caps.difference(manifest_caps))
            stale_caps = sorted(manifest_caps.difference(code_caps))
            details = []
            if missing_caps:
                details.append(f"missing {', '.join(missing_caps)}")
            if stale_caps:
                details.append(f"stale {', '.join(stale_caps)}")
            raise ValueError(f"{path} capabilities mismatch for {name}: {'; '.join(details)}")
        manifest_secret_options = set(manifest.commandlet_secret_options.get(name, ()))
        code_secret_options = {option.name for option in by_name[name].spec.options if option.secret}
        if manifest_secret_options != code_secret_options:
            missing_options = sorted(code_secret_options.difference(manifest_secret_options))
            stale_options = sorted(manifest_secret_options.difference(code_secret_options))
            details = []
            if missing_options:
                details.append(f"missing {', '.join(missing_options)}")
            if stale_options:
                details.append(f"stale {', '.join(stale_options)}")
            raise ValueError(f"{path} secret_options mismatch for {name}: {'; '.join(details)}")
    return tuple(by_name[name] for name in sorted(manifest.commandlets))


def enforce_trigger_manifest(
    manifest: PluginManifest,
    triggers: tuple[TriggerSpec, ...],
    path: Path,
) -> tuple[TriggerSpec, ...]:
    """Return manifest-declared trigger specs and reject drift from code."""
    declared = {trigger.name: trigger for trigger in manifest.triggers}
    exposed: dict[str, TriggerSpec] = {}
    for trigger in triggers:
        if trigger.name in exposed:
            raise ValueError(f"{path} duplicate trigger from code: {trigger.name}")
        exposed[trigger.name] = trigger
    missing = sorted(declared.keys() - exposed.keys())
    if missing:
        raise ValueError(f"{path} declares missing triggers: {', '.join(missing)}")
    undeclared = sorted(exposed.keys() - declared.keys())
    if undeclared:
        raise ValueError(f"{path} exposes undeclared triggers: {', '.join(undeclared)}")
    for name in sorted(declared):
        if declared[name] != exposed[name]:
            raise ValueError(f"{path} trigger mismatch for {name}")
    return tuple(declared[name] for name in sorted(declared))


def load_package_manifest(package_name: str, entry: str) -> PluginManifest | None:
    """Load a bundled sidecar manifest before importing plugin code."""
    parts = entry.split(".")
    manifest = resources.files(package_name)
    for part in (*parts[:-1], f"{parts[-1]}.plugin.toml"):
        manifest = manifest.joinpath(part)
    if not manifest.is_file():
        return None
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{manifest} must contain TOML tables")
    return parse_plugin_manifest_data(data, str(manifest))


def table_value(data: dict[str, Any], key: str, source: str) -> dict[str, Any]:
    """Return one TOML table from a manifest."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{source} [{key}] must be a table")
    return value


def bool_field(data: dict[str, Any], key: str, source: str, context: str = "plugin") -> bool:
    """Return a boolean manifest field."""
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{source} {context}.{key} must be true or false")
    return value


def list_field(data: dict[str, Any], key: str, source: str) -> list[Any]:
    """Return a list manifest field."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} plugin.{key} must be a list")
    return value


def string_list_field(data: dict[str, Any], key: str, source: str, context: str) -> tuple[str, ...]:
    """Return an optional list field that must contain only non-empty strings."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.{key} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source} {context}.{key} entry {index} must be a string")
    return tuple(value)


def load_module_defaults(module: ModuleType, plugin: Commandlet, varstore: VarStore) -> None:
    """Import module-level DEFAULTS into the shared VarStore."""
    defaults = getattr(module, "DEFAULTS", None)
    if isinstance(defaults, dict):
        varstore.update_prefixed(plugin.spec.name, defaults)


def load_defaults_file(plugin_dir: Path, plugin: Commandlet, varstore: VarStore) -> None:
    """Load filesystem plugin defaults from TOML, with JSON compatibility."""
    path = first_existing(plugin_dir / "defaults.toml", plugin_dir / "defaults.json")
    if path is None:
        return
    values = load_data_file(path)
    varstore.update_prefixed(plugin.spec.name, values.get("defaults", values))


def parse_plugin_config(path: Path) -> list[str]:
    """Parse TOML, JSON, or minimal YAML-style plugin config files."""
    text = path.read_text()
    if path.suffix in {".json", ".toml"}:
        data: Any = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
        return list(data.get("default_plugins", []))
    entries: list[str] = []
    in_default_plugins = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "default_plugins:":
            in_default_plugins = True
            continue
        if in_default_plugins and line.startswith("- "):
            entries.append(line[2:].strip())
        elif not raw_line.startswith((" ", "\t")):
            in_default_plugins = False
    return entries


def parse_package_plugin_config(package_name: str, config_name: str) -> list[str]:
    """Read the bundled plugin config from package resources."""
    config = resources.files(package_name).joinpath(config_name)
    text = config.read_text(encoding="utf-8")
    data: Any = tomllib.loads(text) if config_name.endswith(".toml") else json.loads(text)
    return list(data.get("default_plugins", []))


def provider_name(entry: str) -> str:
    """Derive provider name from a dotted plugin config entry."""
    return entry.split(".", 1)[0] if "." in entry else entry


def first_existing(*paths: Path) -> Path | None:
    """Return the first existing path in priority order."""
    return next((path for path in paths if path.exists()), None)
