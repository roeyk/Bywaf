#!/usr/bin/env python3
"""Command-line tool for building signed plugin catalogs.

Provides catalog generation and signing for filesystem plugin directories so the
framework can verify external plugin metadata before loading.

Used by:
- maintainers and release workflows: publish trusted external plugin catalogs.
- catalog tests and smoke scripts: validate trust metadata generation."""


from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_SCHEMA = "bywaf.plugin-catalog.v1"
SIGNATURE_ALGORITHM = "ed25519"


def build_catalog(
    root: Path = ROOT,
    *,
    plugin_root: Path | None = None,
    plugin_config: Path | None = None,
    source: str = "bundled",
) -> dict[str, Any]:
    """Build an unsigned catalog from plugin config and sidecars."""
    plugins_root = plugin_root or root / "bywaf" / "plugins"
    config_path = plugin_config or plugins_root / "plugins.toml"
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    entries = config.get("default_plugins", [])
    if not isinstance(entries, list):
        raise ValueError(f"{config_path} default_plugins must be a list")
    filesystem_layout = plugin_root is not None
    return {
        "schema": CATALOG_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "plugins": [
            catalog_plugin_entry(plugins_root, str(entry), root=root, filesystem_layout=filesystem_layout)
            for entry in entries
        ],
    }


def catalog_plugin_entry(
    plugins_root: Path,
    dotted_entry: str,
    *,
    root: Path = ROOT,
    filesystem_layout: bool = False,
) -> dict[str, Any]:
    """Return one plugin catalog row from source and sidecar metadata."""
    if filesystem_layout:
        module_path = plugins_root / dotted_entry / "plugin.py"
        manifest_path = plugins_root / dotted_entry / "bywaf.plugin.toml"
    else:
        parts = dotted_entry.split(".")
        package_dir = plugins_root.joinpath(*parts)
        if package_dir.is_dir():
            module_path = package_dir / "__init__.py"
            package_manifest = package_dir / "bywaf.plugin.toml"
            sidecar_manifest = plugins_root.joinpath(*parts[:-1], f"{parts[-1]}.plugin.toml")
            manifest_path = package_manifest if package_manifest.exists() else sidecar_manifest
        else:
            module_path = package_dir.with_suffix(".py")
            manifest_path = plugins_root.joinpath(*parts[:-1], f"{parts[-1]}.plugin.toml")
    if not module_path.exists():
        raise FileNotFoundError(f"missing plugin module: {module_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing plugin manifest: {manifest_path}")
    manifest_data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    plugin_data = table_value(manifest_data, "plugin")
    commandlet_rows = manifest_data.get("commandlets", [])
    if not isinstance(commandlet_rows, list):
        raise ValueError(f"{manifest_path} commandlets must be a list")
    library_backed = bool_value(plugin_data, "library_backed", manifest_path, "plugin")
    process_wrapped = bool_value(plugin_data, "process_wrapped", manifest_path, "plugin")
    native = bool_value(plugin_data, "native", manifest_path, "plugin", default=not (library_backed or process_wrapped))
    return {
        "entry": dotted_entry,
        "module": relative_posix(module_path, root=root),
        "manifest": relative_posix(manifest_path, root=root),
        "module_sha256": sha256_file(module_path),
        "manifest_sha256": sha256_file(manifest_path),
        "traits": {
            "native": native,
            "library_backed": library_backed,
            "process_wrapped": process_wrapped,
            "service": bool_value(plugin_data, "service", manifest_path, "plugin"),
        },
        "roles": list(string_list_value(plugin_data, "roles", manifest_path, "plugin")),
        "commandlets": catalog_commandlet_entries(commandlet_rows, manifest_path),
        "triggers": catalog_trigger_entries(manifest_data, manifest_path),
    }


def catalog_commandlet_entries(commandlet_rows: list[Any], manifest_path: Path) -> list[dict[str, Any]]:
    """Return strict commandlet metadata rows from one sidecar manifest."""
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(commandlet_rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{manifest_path} commandlets entry {index} must be a table")
        context = f"commandlets entry {index}"
        rows.append(
            {
                "name": required_string(row, "name", manifest_path, context),
                "capabilities": list(string_list_value(row, "capabilities", manifest_path, context)),
                "secret_options": list(string_list_value(row, "secret_options", manifest_path, context)),
                "provider_variables": list(string_list_value(row, "provider_variables", manifest_path, context)),
                "secret_provider_variables": list(string_list_value(row, "secret_provider_variables", manifest_path, context)),
            }
        )
    return rows


def catalog_trigger_entries(manifest_data: dict[str, Any], manifest_path: Path) -> list[dict[str, Any]]:
    """Return trigger metadata declared by one plugin sidecar manifest."""
    trigger_rows = manifest_data.get("triggers", [])
    if not isinstance(trigger_rows, list):
        raise ValueError(f"{manifest_path} triggers must be a list")
    rows: list[dict[str, Any]] = []
    for index, trigger in enumerate(trigger_rows, start=1):
        if not isinstance(trigger, dict):
            raise ValueError(f"{manifest_path} triggers entry {index} must be a table")
        context = f"triggers entry {index}"
        payload_equals = trigger.get("payload_equals", {})
        if not isinstance(payload_equals, dict):
            raise ValueError(f"{manifest_path} {context}.payload_equals must be a table")
        for key, value in payload_equals.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{manifest_path} {context}.payload_equals keys must be strings")
            if not isinstance(value, str):
                raise ValueError(f"{manifest_path} {context}.payload_equals values must be strings")
        rows.append(
            {
                "name": required_string(trigger, "name", manifest_path, context),
                "topic": required_string(trigger, "topic", manifest_path, context),
                "action_command": required_string(trigger, "action_command", manifest_path, context),
                "action_mode": optional_string(trigger, "action_mode", manifest_path, context, default="service"),
                "description": optional_string(trigger, "description", manifest_path, context, default=""),
                "capability": optional_string(trigger, "capability", manifest_path, context),
                "payload_equals": payload_equals,
                "active_job": bool_value(trigger, "active_job", manifest_path, context),
                "exclude_commandlets": list(string_list_value(trigger, "exclude_commandlets", manifest_path, context)),
                "suppress_self_trigger": bool_value(trigger, "suppress_self_trigger", manifest_path, context, default=True),
            }
        )
    return rows


def required_string(data: dict[str, Any], key: str, source: Path, context: str) -> str:
    """Return a required non-empty string metadata field."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def optional_string(
    data: dict[str, Any],
    key: str,
    source: Path,
    context: str,
    *,
    default: str | None = None,
) -> str | None:
    """Return an optional string metadata field."""
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def bool_value(data: dict[str, Any], key: str, source: Path, context: str, *, default: bool = False) -> bool:
    """Return an optional boolean metadata field."""
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{source} {context}.{key} must be true or false")
    return value


def string_list_value(data: dict[str, Any], key: str, source: Path, context: str) -> tuple[str, ...]:
    """Return an optional list containing only non-empty strings."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.{key} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source} {context}.{key} entry {index} must be a string")
    return tuple(value)


def table_value(data: dict[str, Any], key: str) -> dict[str, Any]:
    """Return one TOML table."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"[{key}] must be a table")
    return value


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_posix(path: Path, *, root: Path = ROOT) -> str:
    """Return a repository-relative POSIX path."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def canonical_catalog_bytes(catalog: dict[str, Any]) -> bytes:
    """Return stable bytes used for signature creation and verification."""
    unsigned = {key: value for key, value in catalog.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    """Write pretty JSON with stable key ordering."""
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from disk."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def cryptography_primitives():
    """Import optional signing primitives with a clear installation error."""
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit("install signing support with: python -m pip install 'cryptography>=42'") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def generate_key(private_path: Path, public_path: Path) -> None:
    """Generate an encrypted Ed25519 signing keypair."""
    _invalid, serialization, private_cls, _public_cls = cryptography_primitives()
    passphrase = prompt_new_passphrase()
    private_key = private_cls.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)
    public_path.write_bytes(public_bytes)


def prompt_new_passphrase() -> bytes:
    """Prompt for a new private-key passphrase."""
    first = getpass.getpass("Private key passphrase: ").encode("utf-8")
    second = getpass.getpass("Confirm passphrase: ").encode("utf-8")
    if first != second:
        raise SystemExit("passphrases do not match")
    if not first:
        raise SystemExit("empty passphrases are not allowed")
    return first


def sign_catalog(catalog_path: Path, private_path: Path, signer: str, output_path: Path) -> None:
    """Sign a catalog with an encrypted Ed25519 private key."""
    _invalid, serialization, _private_cls, _public_cls = cryptography_primitives()
    catalog = load_json(catalog_path)
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=getpass.getpass("Private key passphrase: ").encode("utf-8"),
    )
    signature = private_key.sign(canonical_catalog_bytes(catalog))
    catalog["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "signer": signer,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "public_key_sha256": hashlib.sha256(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest(),
        "value": base64.b64encode(signature).decode("ascii"),
    }
    write_json(output_path, catalog)


def verify_catalog(catalog_path: Path, public_path: Path) -> bool:
    """Verify a signed catalog against a public key."""
    invalid_signature, serialization, _private_cls, public_cls = cryptography_primitives()
    catalog = load_json(catalog_path)
    signature = catalog.get("signature")
    if not isinstance(signature, dict):
        raise SystemExit("catalog has no signature")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        raise SystemExit(f"unsupported signature algorithm: {signature.get('algorithm')}")
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(public_key, public_cls):
        raise SystemExit("public key is not an Ed25519 key")
    try:
        public_key.verify(base64.b64decode(str(signature["value"])), canonical_catalog_bytes(catalog))
    except invalid_signature:
        return False
    return True


def check_catalog_tree(catalog_path: Path, root: Path = ROOT) -> list[str]:
    """Return problems if a catalog no longer matches the plugin tree."""
    catalog = load_json(catalog_path)
    source = str(catalog.get("source") or "bundled")
    current = build_catalog(root, source=source)
    problems: list[str] = []
    if catalog.get("schema") != CATALOG_SCHEMA:
        problems.append(f"unsupported schema: {catalog.get('schema')}")
    if catalog.get("source") != current.get("source"):
        problems.append("catalog source mismatch")
    catalog_plugins = catalog.get("plugins")
    current_plugins = current.get("plugins")
    if not isinstance(catalog_plugins, list):
        problems.append("catalog plugins must be a list")
        return problems
    if catalog_plugins != current_plugins:
        problems.extend(plugin_catalog_differences(catalog_plugins, current_plugins))
    return problems


def plugin_catalog_differences(catalog_plugins: list[Any], current_plugins: Any) -> list[str]:
    """Return human-readable differences between catalog and current tree."""
    if not isinstance(current_plugins, list):
        return ["current plugin catalog build did not produce a plugin list"]
    problems: list[str] = []
    current_by_entry: dict[str, Any] = {}
    for row in current_plugins:
        if isinstance(row, dict) and isinstance(row.get("entry"), str):
            current_by_entry[str(row["entry"])] = row
    catalog_by_entry: dict[str, Any] = {}
    for row in catalog_plugins:
        if isinstance(row, dict) and isinstance(row.get("entry"), str):
            catalog_by_entry[str(row["entry"])] = row
    for entry in sorted(set(catalog_by_entry) - set(current_by_entry)):
        problems.append(f"catalog lists missing plugin: {entry}")
    for entry in sorted(set(current_by_entry) - set(catalog_by_entry)):
        problems.append(f"catalog omits plugin: {entry}")
    for entry in sorted(set(catalog_by_entry) & set(current_by_entry)):
        if catalog_by_entry[entry] != current_by_entry[entry]:
            problems.append(f"catalog metadata/hash mismatch: {entry}")
    return problems


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_catalog.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build an unsigned bundled plugin catalog")
    build.add_argument("--output", "-o", required=True, type=Path)
    build.add_argument("--plugin-root", type=Path, help="filesystem plugin root to catalog")
    build.add_argument("--plugin-config", type=Path, help="plugin config to catalog")
    build.add_argument("--source", default="bundled", help="catalog source label")

    generate = subparsers.add_parser("generate-key", help="generate an encrypted Ed25519 keypair")
    generate.add_argument("--private", required=True, type=Path)
    generate.add_argument("--public", required=True, type=Path)

    sign = subparsers.add_parser("sign", help="sign a catalog")
    sign.add_argument("--catalog", required=True, type=Path)
    sign.add_argument("--private", required=True, type=Path)
    sign.add_argument("--signer", required=True)
    sign.add_argument("--output", "-o", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="verify a signed catalog")
    verify.add_argument("--catalog", required=True, type=Path)
    verify.add_argument("--public", required=True, type=Path)
    verify.add_argument("--check-tree", action="store_true", help="also verify catalog hashes against this checkout")

    check = subparsers.add_parser("check", help="verify catalog hashes against this checkout")
    check.add_argument("--catalog", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the maintainer catalog tool."""
    args = build_parser().parse_args(argv)
    if args.command == "build":
        write_json(
            args.output,
            build_catalog(plugin_root=args.plugin_root, plugin_config=args.plugin_config, source=args.source),
        )
        return 0
    if args.command == "generate-key":
        generate_key(args.private, args.public)
        return 0
    if args.command == "sign":
        sign_catalog(args.catalog, args.private, args.signer, args.output)
        return 0
    if args.command == "verify":
        if verify_catalog(args.catalog, args.public):
            if args.check_tree:
                problems = check_catalog_tree(args.catalog)
                if problems:
                    for problem in problems:
                        print(problem, file=sys.stderr)
                    return 1
            print("signature ok")
            return 0
        print("signature invalid", file=sys.stderr)
        return 1
    if args.command == "check":
        problems = check_catalog_tree(args.catalog)
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
        print("catalog tree ok")
        return 0
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
