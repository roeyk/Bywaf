"""Signed plugin manifest packaging install-path tests."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from bywaf.app import main
from bywaf.db import EventStore
from tests.packaging_install.support import (
    cryptography_available,
    sign_plugin_manifest,
    write_manifest_signing_key,
    write_plugin,
)


class PackagingInstallSignedManifestTests(unittest.TestCase):
    """Groups regression coverage for signed plugin manifest packaging install-path tests."""
    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_loads_external_plugin_with_signed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            plugin_dir = write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            private_path, public_path = write_manifest_signing_key(tmp_path)
            sign_plugin_manifest(plugin_dir / "bywaf.plugin.toml", private_path)

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
                        "--plugin-manifest-key",
                        str(public_path),
                        "--allow-unsigned-plugins",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())
            verified = EventStore(tmp_path / "db.sqlite3").events_for_topic("plugin.manifest.verified")[0]
            self.assertEqual(verified.payload["entry"], "local/userprobe")

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_cli_run_rejects_tampered_signed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "plugins"
            plugin_dir = write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            private_path, public_path = write_manifest_signing_key(tmp_path)
            manifest_path = plugin_dir / "bywaf.plugin.toml"
            sign_plugin_manifest(manifest_path, private_path)
            manifest_path.write_text(manifest_path.read_text(encoding="utf-8").replace("native = true", "native = false"))

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(tmp_path / "db.sqlite3"),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--plugin-manifest-key",
                        str(public_path),
                        "--allow-unsigned-plugins",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(tmp_path / "db.sqlite3").events_for_topic("plugin.manifest.rejected")[0]
            self.assertIn("manifest digest mismatch", rejected.payload["reason"])


if __name__ == "__main__":
    unittest.main()
