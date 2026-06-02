"""Packaging version, key namespace, and install root tests."""

from pathlib import Path
import contextlib
import importlib.resources
import io
import re
import tempfile
import tomllib
import unittest

import bywaf
from bywaf.app import main, make_runner
from bywaf.db import EventStore
from tests.packaging_install.support import write_plugin


class PackagingInstallVersionAndRootTests(unittest.TestCase):
    def test_release_package_versions_are_aligned(self):
        version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        rpm_spec = Path("packaging/rpm/bywaf.spec").read_text(encoding="utf-8")
        debian_changelog = Path("debian/changelog").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertEqual(bywaf.__version__, version)
        self.assertRegex(rpm_spec, rf"%global bywaf_version %{{!\?bywaf_version:{re.escape(version)}}}")
        self.assertTrue(debian_changelog.startswith(f"bywaf ({version}-1) "))
        self.assertIn(f"dist/bywaf-{version}-py3-none-any.whl", readme)

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


if __name__ == "__main__":
    unittest.main()
