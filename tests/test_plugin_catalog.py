"""Tests for plugin catalog behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

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

    def test_built_catalog_includes_trigger_metadata(self):
        catalog = build_catalog()
        watchdog = next(row for row in catalog["plugins"] if row["entry"] == "runtime.watchdog")

        self.assertEqual(watchdog["triggers"][0]["name"], "network-access-starts-watchdog")
        self.assertEqual(watchdog["triggers"][0]["action_mode"], "service")

    def test_catalog_reads_triggers_from_manifest_without_importing_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_root = root / "plugins"
            plugin_dir = plugin_root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text("raise RuntimeError('catalog imported plugin code')\n")
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n\n'
                "[[triggers]]\n"
                'name = "example-trigger"\n'
                'topic = "example.event"\n'
                'action_command = "example"\n'
                'action_mode = "background"\n'
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["scanners/example"]\n')

            catalog = build_catalog(root, plugin_root=plugin_root, plugin_config=config, source="test")

            self.assertEqual(catalog["plugins"][0]["triggers"][0]["name"], "example-trigger")

    def test_catalog_reads_event_schemas_from_manifest_without_importing_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_root = root / "plugins"
            plugin_dir = plugin_root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text("raise RuntimeError('catalog imported plugin code')\n")
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n\n'
                "[[event_schemas]]\n"
                'topic = "example.session.observed"\n'
                'summary = "Example session fact."\n\n'
                "[[event_schemas.fields]]\n"
                'name = "host"\n'
                'type = "str"\n'
                "required = true\n"
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["scanners/example"]\n')

            catalog = build_catalog(root, plugin_root=plugin_root, plugin_config=config, source="test")

            self.assertEqual(catalog["plugins"][0]["event_schemas"][0]["topic"], "example.session.observed")
            self.assertEqual(catalog["plugins"][0]["event_schemas"][0]["fields"][0]["name"], "host")

    def test_catalog_treats_single_segment_filesystem_entry_as_plugin_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_root = root / "plugins"
            plugin_dir = plugin_root / "myplugin"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text("def plugin():\n    raise RuntimeError('not imported')\n")
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["myplugin"]\n')

            catalog = build_catalog(root, plugin_root=plugin_root, plugin_config=config, source="test")

            self.assertEqual(catalog["plugins"][0]["module"], "plugins/myplugin/plugin.py")
            self.assertEqual(catalog["plugins"][0]["manifest"], "plugins/myplugin/bywaf.plugin.toml")

    def test_catalog_supports_bundled_package_plugin_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_root = root / "bywaf" / "plugins"
            plugin_dir = plugin_root / "http" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "__init__.py").write_text("def plugin():\n    raise RuntimeError('not imported')\n")
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = plugin_root / "plugins.toml"
            config.write_text('default_plugins = ["http.example"]\n')

            catalog = build_catalog(root, plugin_config=config, source="test")

            self.assertEqual(catalog["plugins"][0]["module"], "bywaf/plugins/http/example/__init__.py")
            self.assertEqual(catalog["plugins"][0]["manifest"], "bywaf/plugins/http/example/bywaf.plugin.toml")

    def test_catalog_rejects_string_boolean_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plugin_root = write_catalog_fixture(
                tmp,
                "[plugin]\n"
                'service = "false"\n\n'
                "[[commandlets]]\n"
                'name = "example"\n',
            )

            with self.assertRaisesRegex(ValueError, "plugin.service must be true or false"):
                build_catalog(root, plugin_root=plugin_root, plugin_config=root / "plugins.toml", source="test")

    def test_catalog_rejects_non_string_capability_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plugin_root = write_catalog_fixture(
                tmp,
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = [123]\n",
            )

            with self.assertRaisesRegex(ValueError, "capabilities entry 1 must be a string"):
                build_catalog(root, plugin_root=plugin_root, plugin_config=root / "plugins.toml", source="test")

    def test_catalog_rejects_non_string_trigger_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plugin_root = write_catalog_fixture(
                tmp,
                "[[commandlets]]\n"
                'name = "example"\n\n'
                "[[triggers]]\n"
                'name = "example-trigger"\n'
                'topic = "example.event"\n'
                'action_command = "example"\n'
                "payload_equals = { count = 3 }\n",
            )

            with self.assertRaisesRegex(ValueError, "payload_equals values must be strings"):
                build_catalog(root, plugin_root=plugin_root, plugin_config=root / "plugins.toml", source="test")

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


def write_catalog_fixture(tmp: str, manifest: str) -> tuple[Path, Path]:
    root = Path(tmp)
    plugin_root = root / "plugins"
    plugin_dir = plugin_root / "myplugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.py").write_text("def plugin():\n    raise RuntimeError('not imported')\n")
    (plugin_dir / "bywaf.plugin.toml").write_text(manifest)
    (root / "plugins.toml").write_text('default_plugins = ["myplugin"]\n')
    return root, plugin_root
