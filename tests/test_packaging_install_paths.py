"""Tests for packaging install paths behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

# pyright: reportMissingImports=false

from pathlib import Path
import contextlib
import io
import importlib.resources
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import main, make_runner
from bywaf.db import EventStore
from bywaf.registry import plugin_manifest_signature_block
from scripts.plugin_catalog import build_catalog, sign_catalog, write_json


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


PLUGIN_TEMPLATE = """\
from bywaf.plugin import CommandSpec


class {class_name}:
    spec = CommandSpec({name!r}, {description!r}, emits=({topic!r},))

    def run(self, context, args, input_events):
        yield {{"source": {source!r}}}


def plugin():
    return {class_name}()
"""


def write_plugin(root: Path, entry: str, name: str, source: str) -> Path:
    """Create a minimal filesystem plugin and config entry for install-path tests."""
    plugin_dir = root / entry
    plugin_dir.mkdir(parents=True)
    class_name = "".join(part.capitalize() for part in name.split("_"))
    (plugin_dir / "plugin.py").write_text(
        PLUGIN_TEMPLATE.format(
            class_name=class_name,
            name=name,
            description=f"{source} test plugin",
            topic=f"{name}.event",
            source=source,
        )
    )
    (plugin_dir / "defaults.toml").write_text(f'[defaults]\norigin = "{source}"\n')
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[plugin]\n"
        "native = true\n\n"
        "[[commandlets]]\n"
        f'name = "{name}"\n'
        "capabilities = []\n"
    )
    return plugin_dir


def write_signed_catalog(tmp_path: Path, root: Path, config: Path) -> tuple[Path, Path]:
    """Create a signed catalog and return (signed_catalog, public_key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    catalog = tmp_path / "catalog.json"
    signed = tmp_path / "catalog.signed.json"
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
    write_json(catalog, build_catalog(plugin_root=root, plugin_config=config, source="local"))
    with patch("getpass.getpass", return_value="passphrase"):
        sign_catalog(catalog, private_path, "unit-test", signed)
    return signed, public_path


def write_manifest_signing_key(tmp_path: Path) -> tuple[Path, Path]:
    """Create an encrypted manifest signing keypair and return (private, public)."""
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


def sign_plugin_manifest(manifest_path: Path, private_path: Path) -> None:
    """Append a framework manifest signature block to one manifest."""
    import tomllib

    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    block = plugin_manifest_signature_block(data, private_path, passphrase="passphrase")
    lines = ["", "[bywaf_signature]"]
    for key in ("schema", "algorithm", "digest_algorithm", "digest", "value"):
        lines.append(f'{key} = "{block[key]}"')
    manifest_path.write_text(manifest_path.read_text(encoding="utf-8").rstrip() + "\n" + "\n".join(lines) + "\n")


class PackagingInstallPathTests(unittest.TestCase):
    def test_packaged_key_namespace_contains_public_key_policy_docs(self):
        key_docs = importlib.resources.files("bywaf.keys").joinpath("README.md")
        key_placeholder = importlib.resources.files("bywaf.keys").joinpath(
            "plugin-manifest.pub.pem.example"
        )

        self.assertTrue(key_docs.is_file())
        self.assertIn("Private manifest-signing keys", key_docs.read_text(encoding="utf-8"))
        self.assertTrue(key_placeholder.is_file())
        self.assertIn("not a public key", key_placeholder.read_text(encoding="utf-8"))

    def test_user_local_shaped_plugin_root_loads_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp, "home", "alice")
            root = home / ".bywaf" / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')

            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config, forced_plugins=True)

            self.assertIn("userprobe", runner.registry.names())
            self.assertEqual(runner.registry.varstore.get("local/userprobe.origin"), "user-local")

    def test_system_wide_shaped_plugin_root_loads_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "usr", "share", "bywaf", "plugins")
            write_plugin(root, "site/systemprobe", "systemprobe", "system-wide")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["site/systemprobe"]\n')

            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config, forced_plugins=True)

            self.assertIn("systemprobe", runner.registry.names())
            self.assertEqual(runner.registry.varstore.get("site/systemprobe.origin"), "system-wide")

    def test_cli_run_uses_explicit_plugin_root_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "--database",
                        str(Path(tmp, "db.sqlite3")),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--allow-unsigned-plugins",
                        "--allow-unsigned-plugin-manifests",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())

    def test_cli_run_rejects_unsigned_manifest_without_manifest_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/userprobe"]\n')
            db_path = Path(tmp, "db.sqlite3")

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "--database",
                        str(db_path),
                        "--plugin-root",
                        str(root),
                        "--plugin-config",
                        str(config),
                        "--allow-unsigned-plugins",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 1)
            rejected = EventStore(db_path).events_for_topic("plugin.manifest.rejected")[0]
            self.assertIn("manifest signature is missing", rejected.payload["reason"])

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
