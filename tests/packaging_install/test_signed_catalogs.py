"""Signed plugin catalog packaging install-path tests.

Coverage focus: packaging install signed catalogs regression behavior.
"""

from pathlib import Path
import contextlib
import io
import json
import tempfile
import unittest

from bywaf.app import main
from bywaf.db import EventStore
from tests.packaging_install.support import cryptography_available, write_plugin, write_signed_catalog


class PackagingInstallSignedCatalogTests(unittest.TestCase):
    """Groups regression coverage for signed plugin catalog packaging install-path tests."""
    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_loads_external_plugin_with_signed_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "home" / "alice" / ".bywaf" / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            db_path = tmp_path / "db.sqlite3"

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())
            db = EventStore(db_path)
            self.assertEqual(db.events_for_topic("plugin.catalog.verified")[0].payload["entries"], 1)
            self.assertEqual(db.events_for_topic("plugin.catalog.entry.verified")[0].payload["entry"], "local/userprobe")

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_tampered_plugin_py_after_signed_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            plugin_dir = write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            (plugin_dir / "plugin.py").write_text((plugin_dir / "plugin.py").read_text() + "\n# tampered\n")
            db_path = tmp_path / "db.sqlite3"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.catalog.entry.rejected")[0]
            self.assertEqual(rejected.payload["entry"], "local/userprobe")

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_tampered_manifest_after_signed_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            plugin_dir = write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            (plugin_dir / "bywaf.plugin.toml").write_text((plugin_dir / "bywaf.plugin.toml").read_text() + "\n# tampered\n")
            db_path = tmp_path / "db.sqlite3"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.catalog.entry.rejected")[0]
            self.assertEqual(rejected.payload["entry"], "local/userprobe")

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_missing_catalog_key_without_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, _public_path = write_signed_catalog(tmp_path, root, config)
            db_path = tmp_path / "db.sqlite3"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.catalog.rejected")[0]
            self.assertIn("trusted plugin catalog key is missing", rejected.payload["reason"])

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_allows_missing_catalog_key_with_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, _public_path = write_signed_catalog(tmp_path, root, config)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "--database",
                        str(tmp_path / "db.sqlite3"),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--allow-missing-plugin-keys",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_key_fingerprint_mismatch_without_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            data = json.loads(signed.read_text())
            data["signature"]["public_key_sha256"] = "0" * 64
            signed.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            db_path = tmp_path / "db.sqlite3"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.catalog.rejected")[0]
            self.assertIn("fingerprint does not match", rejected.payload["reason"])

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_allows_key_fingerprint_mismatch_with_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            data = json.loads(signed.read_text())
            data["signature"]["public_key_sha256"] = "0" * 64
            signed.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "--database",
                        str(tmp_path / "db.sqlite3"),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "--allow-mismatched-plugin-keys",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_invalid_catalog_signature_even_with_bypasses(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            signed, public_path = write_signed_catalog(tmp_path, root, config)
            data = json.loads(signed.read_text())
            data["plugins"][0]["module_sha256"] = "0" * 64
            signed.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
            db_path = tmp_path / "db.sqlite3"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-catalog",
                        str(signed),
                        "--plugin-catalog-key",
                        str(public_path),
                        "--allow-untrusted-plugins",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.catalog.rejected")[0]
            self.assertIn("signature is invalid", rejected.payload["reason"])


if __name__ == "__main__":
    unittest.main()
