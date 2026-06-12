#!/usr/bin/env python3
"""Tests for smoke plugin catalog signing behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: scripted smoke flow for smoke plugin catalog signing.
- maintainers: document expected behavior through executable examples."""


from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    """Run build, key generation, signing, and verification as a CLI flow."""
    if importlib.util.find_spec("cryptography") is None:
        print("SKIP: cryptography is not installed")
        return 77

    sys.path.insert(0, str(ROOT))
    from scripts.plugin_catalog import main as catalog_main

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        catalog = tmp_path / "catalog.json"
        signed = tmp_path / "catalog.signed.json"
        private_key = tmp_path / "catalog-signing.pem"
        public_key = tmp_path / "catalog-signing.pub.pem"

        if catalog_main(["build", "--output", str(catalog)]) != 0:
            return 1
        with patch("getpass.getpass", side_effect=["test-passphrase", "test-passphrase"]):
            if catalog_main(["generate-key", "--private", str(private_key), "--public", str(public_key)]) != 0:
                return 1
        with patch("getpass.getpass", return_value="test-passphrase"):
            if catalog_main(["sign", "--catalog", str(catalog), "--private", str(private_key), "--signer", "smoke-test", "--output", str(signed)]) != 0:
                return 1
        if catalog_main(["verify", "--catalog", str(signed), "--public", str(public_key), "--check-tree"]) != 0:
            return 1

    print("plugin catalog signing smoke ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
