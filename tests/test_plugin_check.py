"""Tests for the standalone filesystem plugin checker."""
# pyright: reportMissingImports=false

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.plugin_check import check_plugin, main, render_text
from scripts.plugin_manifest_sign import main as sign_manifest_main


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class PluginCheckTests(unittest.TestCase):
    def test_check_plugin_accepts_valid_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["commandlets"], ["example"])
            self.assertEqual(report["triggers"], [])
            self.assertEqual(report["errors"], [])

    def test_check_plugin_reports_manifest_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",), manifest_capabilities=())

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("capabilities mismatch", report["errors"][0])

    def test_check_plugin_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            output = capture_stdout(lambda: main([str(plugin_dir), "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertEqual(data["commandlets"], ["example"])

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


def write_plugin_fixture(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    manifest_capabilities: tuple[str, ...] | None = None,
) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    capability_text = repr(capabilities)
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "class Example:\n"
        f"    spec = CommandSpec('example', 'example plugin', capabilities={capability_text})\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    declared = capabilities if manifest_capabilities is None else manifest_capabilities
    manifest_capability_lines = "".join(f'  "{item}",\n' for item in declared)
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = [\n"
        f"{manifest_capability_lines}"
        "]\n"
    )
    return plugin_dir


def write_manifest_signing_key(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path = tmp_path / "manifest-signing.pem"
    public_path = tmp_path / "manifest-signing.pub.pem"
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
    return private_path, public_path


def capture_stdout(fn):
    import contextlib
    import io

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = fn()
    self_result = result
    if self_result not in (None, 0):
        raise AssertionError(f"expected successful return code, got {self_result}")
    return output.getvalue()


if __name__ == "__main__":
    unittest.main()
