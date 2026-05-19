"""Tests for maintainer-side plugin catalog signing."""
# pyright: reportMissingImports=false

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.plugin_catalog import (
    build_catalog,
    check_catalog_tree,
    sign_catalog,
    verify_catalog,
    write_json,
)


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class PluginCatalogTests(unittest.TestCase):
    def test_built_catalog_matches_current_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog_path = Path(tmp, "catalog.json")
            write_json(catalog_path, build_catalog())

            self.assertEqual(check_catalog_tree(catalog_path), [])

    def test_catalog_check_reports_tampered_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = build_catalog()
            catalog["plugins"][0]["module_sha256"] = "0" * 64
            catalog_path = Path(tmp, "catalog.json")
            write_json(catalog_path, catalog)

            problems = check_catalog_tree(catalog_path)

            self.assertTrue(any("metadata/hash mismatch" in problem for problem in problems))

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_catalog_sign_and_verify(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_path = tmp_path / "catalog-signing.pem"
            public_path = tmp_path / "catalog-signing.pub.pem"
            private_key = Ed25519PrivateKey.generate()
            private_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
                )
            )
            public_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            catalog_path = tmp_path / "catalog.json"
            signed_path = tmp_path / "catalog.signed.json"
            write_json(catalog_path, build_catalog())

            with patch("getpass.getpass", return_value="passphrase"):
                sign_catalog(catalog_path, private_path, "unit-test", signed_path)

            self.assertTrue(verify_catalog(signed_path, public_path))
            self.assertEqual(check_catalog_tree(signed_path), [])

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_catalog_signature_rejects_tampering(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_path = tmp_path / "catalog-signing.pem"
            public_path = tmp_path / "catalog-signing.pub.pem"
            private_key = Ed25519PrivateKey.generate()
            private_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
                )
            )
            public_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            catalog_path = tmp_path / "catalog.json"
            signed_path = tmp_path / "catalog.signed.json"
            write_json(catalog_path, build_catalog())
            with patch("getpass.getpass", return_value="passphrase"):
                sign_catalog(catalog_path, private_path, "unit-test", signed_path)
            tampered = copy.deepcopy(build_catalog())
            tampered["signature"] = __import__("json").loads(signed_path.read_text())["signature"]
            tampered["plugins"][0]["manifest_sha256"] = "0" * 64
            write_json(signed_path, tampered)

            self.assertFalse(verify_catalog(signed_path, public_path))
