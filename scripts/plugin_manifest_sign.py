#!/usr/bin/env python3
"""Sign a plugin sidecar manifest with a direct Ed25519 private key file."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bywaf.registry import plugin_manifest_signature_block  # noqa: E402
from bywaf.toml_support import load_data_file  # noqa: E402


def signature_block_toml(block: dict[str, str]) -> str:
    """Return TOML text for one manifest signature block."""
    lines = ["[bywaf_signature]"]
    for key in ("schema", "algorithm", "digest_algorithm", "digest", "value"):
        lines.append(f'{key} = "{escape_toml_string(block[key])}"')
    return "\n".join(lines) + "\n"


def escape_toml_string(value: str) -> str:
    """Escape TOML basic-string characters used by signature blocks."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def sign_manifest(manifest: Path, private_key: Path, *, passphrase: str | None = None) -> str:
    """Return a TOML signature block for one plugin manifest."""
    data = load_data_file(manifest)
    block = plugin_manifest_signature_block(data, private_key, passphrase=passphrase)
    return signature_block_toml(block)


def build_parser() -> argparse.ArgumentParser:
    """Build the manifest signing CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_manifest_sign.py")
    parser.add_argument("--manifest", required=True, type=Path, help="bywaf.plugin.toml to sign")
    parser.add_argument("--private", required=True, type=Path, help="Ed25519 private key PEM")
    parser.add_argument("--output", type=Path, help="write signed manifest to this path")
    parser.add_argument("--in-place", action="store_true", help="append the signature block to the manifest")
    parser.add_argument("--passphrase-env", help="read the private-key passphrase from this environment variable")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Sign a plugin manifest."""
    args = build_parser().parse_args(argv)
    if args.output and args.in_place:
        raise SystemExit("--output and --in-place are mutually exclusive")
    passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else getpass.getpass("Private key passphrase: ")
    block = sign_manifest(args.manifest, args.private, passphrase=passphrase)
    if args.in_place:
        text = args.manifest.read_text(encoding="utf-8").rstrip() + "\n\n" + block
        args.manifest.write_text(text, encoding="utf-8")
        return 0
    if args.output:
        text = args.manifest.read_text(encoding="utf-8").rstrip() + "\n\n" + block
        args.output.write_text(text, encoding="utf-8")
        return 0
    print(block, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
