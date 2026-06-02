"""Plugin checker tests for test submissions and output."""

from pathlib import Path
import importlib.util
import json
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from scripts.plugin_check import check_plugin, main, render_text
from scripts.plugin_manifest_sign import main as sign_manifest_main
from tests.plugin_check_fixtures import capture_stdout, write_manifest_signing_key, write_plugin_fixture


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class TestSubmissionsAndOutputTests(unittest.TestCase):
    def test_check_plugin_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            output = capture_stdout(lambda: main([str(plugin_dir), "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertEqual(data["commandlets"], ["example"])

    def test_check_plugin_accepts_zip_submission(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            archive = tmp_path / "example.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for path in plugin_dir.rglob("*"):
                    if path.is_file():
                        zipped.write(path, path.relative_to(tmp_path))

            report = check_plugin(archive)

            self.assertTrue(report["ok"])
            self.assertEqual(report["plugin"], str(archive))
            self.assertEqual(report["commandlets"], ["example"])

    def test_check_plugin_temp_checkout_cli_accepts_zip_submission(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            archive = tmp_path / "example.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for path in plugin_dir.rglob("*"):
                    if path.is_file():
                        zipped.write(path, path.relative_to(tmp_path))

            output = capture_stdout(lambda: main([str(archive), "--temp-checkout", "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertTrue(data["temp_checkout"])
            self.assertEqual(data["plugin"], str(archive))
            self.assertEqual(data["submission"], str(archive))

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_check_plugin_verifies_signed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            private_path, public_path = write_manifest_signing_key(tmp_path)
            with patch("getpass.getpass", return_value="passphrase"):
                self.assertEqual(
                    sign_manifest_main(
                        [
                            "--manifest",
                            str(plugin_dir / "bywaf.plugin.toml"),
                            "--private",
                            str(private_path),
                            "--in-place",
                        ]
                    ),
                    0,
                )

            report = check_plugin(plugin_dir, manifest_key=public_path)

            self.assertTrue(report["ok"])
            self.assertEqual(report["manifest_signature"], "verified")

    def test_check_plugin_verify_requires_manifest_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            report = check_plugin(plugin_dir, verify_manifest=True)

            self.assertFalse(report["ok"])
            self.assertIn("--verify requires --manifest-key", report["errors"])

    def test_check_plugin_text_output(self):
        report = {"ok": False, "plugin": "/tmp/missing", "commandlets": [], "triggers": [], "errors": ["missing"]}

        text = render_text(report)

        self.assertIn("failed plugin=/tmp/missing", text)
        self.assertIn("error: missing", text)


if __name__ == "__main__":
    unittest.main()
