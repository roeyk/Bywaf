#!/usr/bin/env python3
"""Maintainer-side plugin catalog builder, signer, and verifier.

This is release-engineering tooling, not a Bywaf commandlet. It signs the
reviewed plugin catalog outside the runtime so Bywaf can later verify official
plugin provenance before loading code.
"""

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


def build_catalog(root: Path = ROOT) -> dict[str, Any]:
    """Build an unsigned catalog from bundled plugin config and sidecars."""
    plugins_root = root / "bywaf" / "plugins"
    config = tomllib.loads((plugins_root / "plugins.toml").read_text(encoding="utf-8"))
    entries = config.get("default_plugins", [])
    if not isinstance(entries, list):
        raise ValueError("bywaf/plugins/plugins.toml default_plugins must be a list")
    return {
        "schema": CATALOG_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": "bundled",
        "plugins": [catalog_plugin_entry(plugins_root, str(entry)) for entry in entries],
    }


def catalog_plugin_entry(plugins_root: Path, dotted_entry: str) -> dict[str, Any]:
    """Return one plugin catalog row from source and sidecar metadata."""
    parts = dotted_entry.split(".")
    module_path = plugins_root.joinpath(*parts).with_suffix(".py")
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
    return {
        "entry": dotted_entry,
        "module": relative_posix(module_path),
        "manifest": relative_posix(manifest_path),
        "module_sha256": sha256_file(module_path),
        "manifest_sha256": sha256_file(manifest_path),
        "traits": {
            "native": bool(plugin_data.get("native", not (plugin_data.get("library_backed") or plugin_data.get("process_wrapped")))),
            "library_backed": bool(plugin_data.get("library_backed", False)),
            "process_wrapped": bool(plugin_data.get("process_wrapped", False)),
            "service": bool(plugin_data.get("service", False)),
        },
        "roles": [str(role) for role in plugin_data.get("roles", [])],
        "commandlets": [
            {
                "name": str(row["name"]),
                "capabilities": [str(value) for value in row.get("capabilities", [])],
                "secret_options": [str(value) for value in row.get("secret_options", [])],
            }
            for row in commandlet_rows
        ],
    }


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


def relative_posix(path: Path) -> str:
    """Return a repository-relative POSIX path."""
    return path.relative_to(ROOT).as_posix()


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


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_catalog.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build an unsigned bundled plugin catalog")
    build.add_argument("--output", "-o", required=True, type=Path)

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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the maintainer catalog tool."""
    args = build_parser().parse_args(argv)
    if args.command == "build":
        write_json(args.output, build_catalog())
        return 0
    if args.command == "generate-key":
        generate_key(args.private, args.public)
        return 0
    if args.command == "sign":
        sign_catalog(args.catalog, args.private, args.signer, args.output)
        return 0
    if args.command == "verify":
        if verify_catalog(args.catalog, args.public):
            print("signature ok")
            return 0
        print("signature invalid", file=sys.stderr)
        return 1
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
