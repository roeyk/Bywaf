"""Tests for external plugin cli smoke behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

# pyright: reportMissingImports=false

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.plugin_catalog import build_catalog, sign_catalog, write_json


ROOT = Path(__file__).resolve().parents[1]


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class ExternalPluginCliSmokeTests(unittest.TestCase):
    def test_plugin_check_script_accepts_valid_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "plugins"
            plugin_dir = write_external_plugin(root, "myplugin", "smokeprobe", "cli-check")

            result = run_python_script("scripts/plugin_check.py", str(plugin_dir), "--json")

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["ok"])
            self.assertEqual(report["commandlets"], ["smokeprobe"])

    def test_plugin_catalog_build_script_accepts_single_segment_external_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_root = tmp_path / "plugins"
            write_external_plugin(plugin_root, "myplugin", "smokeprobe", "catalog-build")
            config = tmp_path / "plugins.toml"
            config.write_text('default_plugins = ["myplugin"]\n')
            catalog = tmp_path / "catalog.json"

            result = run_python_script(
                "scripts/plugin_catalog.py",
                "build",
                "--plugin-root",
                str(plugin_root),
                "--plugin-config",
                str(config),
                "--source",
                "smoke",
                "--output",
                str(catalog),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(catalog.read_text())
            self.assertEqual(data["plugins"][0]["entry"], "myplugin")
            self.assertTrue(data["plugins"][0]["module"].endswith("/plugins/myplugin/plugin.py"))

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_plugin_manifest_sign_script_signs_manifest_for_plugin_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_root = tmp_path / "plugins"
            plugin_dir = write_external_plugin(plugin_root, "myplugin", "smokeprobe", "manifest-sign")
            private_key, public_key = write_signing_key(tmp_path, "manifest-signing")

            sign_result = run_python_script(
                "scripts/plugin_manifest_sign.py",
                "--manifest",
                str(plugin_dir / "bywaf.plugin.toml"),
                "--private",
                str(private_key),
                "--passphrase-env",
                "BYWAF_TEST_KEY_PASSPHRASE",
                "--in-place",
            )

            self.assertEqual(sign_result.returncode, 0, sign_result.stdout + sign_result.stderr)
            self.assertIn("[bywaf_signature]", (plugin_dir / "bywaf.plugin.toml").read_text())
            check_result = run_python_script(
                "scripts/plugin_check.py",
                str(plugin_dir),
                "--manifest-key",
                str(public_key),
                "--verify",
                "--json",
            )
            self.assertEqual(check_result.returncode, 0, check_result.stdout + check_result.stderr)
            report = json.loads(check_result.stdout)
            self.assertEqual(report["manifest_signature"], "verified")

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_bywaf_cli_runs_external_plugin_with_signed_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_root = tmp_path / "plugins"
            write_external_plugin(plugin_root, "myplugin", "smokeprobe", "signed-cli")
            config = tmp_path / "plugins.toml"
            config.write_text('default_plugins = ["myplugin"]\n')
            signed, public_key = write_signed_catalog(tmp_path, plugin_root, config)

            result = run_module(
                "bywaf",
                "--database",
                str(tmp_path / "bywaf.sqlite3"),
                "--plugin-root",
                str(plugin_root),
                "--plugin-config",
                str(config),
                "--plugin-catalog",
                str(signed),
                "--plugin-catalog-key",
                str(public_key),
                "smokeprobe",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("'source': 'signed-cli'", result.stdout)


def write_external_plugin(root: Path, entry: str, commandlet: str, source: str) -> Path:
    plugin_dir = root / entry
    plugin_dir.mkdir(parents=True)
    class_name = "".join(part.capitalize() for part in commandlet.split("_"))
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n\n"
        f"class {class_name}:\n"
        f"    spec = CommandSpec({commandlet!r}, 'smoke plugin')\n"
        "    def run(self, context, args, input_events):\n"
        f"        yield {{'source': {source!r}}}\n\n"
        "def plugin():\n"
        f"    return {class_name}()\n"
    )
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        "native = true\n\n"
        "[[commandlets]]\n"
        f'name = "{commandlet}"\n'
        "capabilities = []\n"
    )
    return plugin_dir


def write_signed_catalog(tmp_path: Path, plugin_root: Path, config: Path) -> tuple[Path, Path]:
    catalog = tmp_path / "catalog.json"
    signed = tmp_path / "catalog.signed.json"
    private_path, public_path = write_signing_key(tmp_path, "catalog-signing")
    write_json(catalog, build_catalog(tmp_path, plugin_root=plugin_root, plugin_config=config, source="smoke"))
    with patch("getpass.getpass", return_value="passphrase"):
        sign_catalog(catalog, private_path, "smoke-test", signed)
    return signed, public_path


def write_signing_key(tmp_path: Path, name: str) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path = tmp_path / f"{name}.pem"
    public_path = tmp_path / f"{name}.pub.pem"
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


def run_python_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=smoke_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def run_module(module: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=ROOT,
        env=smoke_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def smoke_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["BYWAF_TEST_KEY_PASSPHRASE"] = "passphrase"
    return env


if __name__ == "__main__":
    unittest.main()
