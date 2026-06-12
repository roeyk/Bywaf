"""Packaging version, key namespace, and install root tests.

Coverage focus: packaging install versions and roots regression behavior.
"""

from pathlib import Path
import contextlib
import importlib.resources
import io
import json
import re
import tempfile
import tomllib
import unittest

import bywaf
from bywaf.app import main, make_runner
from bywaf.db import EventStore
from tests.packaging_install.support import write_plugin


class PackagingInstallVersionAndRootTests(unittest.TestCase):
    """Groups regression coverage for packaging version, key namespace, and install root tests."""
    def test_release_package_versions_are_aligned(self):
        """Protect release package versions are aligned behavior from regressions."""
        version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        rpm_spec = Path("packaging/rpm/bywaf.spec").read_text(encoding="utf-8")
        debian_changelog = Path("debian/changelog").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertEqual(bywaf.__version__, version)
        self.assertRegex(rpm_spec, rf"%global bywaf_version %{{!\?bywaf_version:{re.escape(version)}}}")
        self.assertTrue(debian_changelog.startswith(f"bywaf ({version}-1) "))
        self.assertIn(f"dist/bywaf-{version}-py3-none-any.whl", readme)

    def test_packaged_key_namespace_contains_public_key_policy_docs(self):
        """Protect packaged key namespace contains public key policy docs behavior from regressions."""
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

    def test_filesystem_config_validates_declared_plugin_dependencies_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/provider", "provider", "provider")
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/provider"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer", "local/provider"]\n')

            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config, forced_plugins=True)

            self.assertIn("consumer", runner.registry.names())
            self.assertIn("provider", runner.registry.names())

    def test_filesystem_config_auto_loads_available_declared_plugin_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/provider", "provider", "provider")
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/provider"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer"]\n')
            db_path = Path(tmp, "db.sqlite3")

            runner = make_runner(db_path, plugin_root=root, plugin_config=config, forced_plugins=True)

            self.assertIn("consumer", runner.registry.names())
            self.assertIn("provider", runner.registry.names())
            self.assertEqual(runner.registry.provider_commandlet_names("local/provider"), ["provider"])
            events = EventStore(db_path).events_for_topic("plugin.dependency.auto_loaded")
            self.assertEqual(events[-1].payload["plugin"], "local/provider")

    def test_cli_plugin_graph_shows_filesystem_dependency_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/provider", "provider", "provider")
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/provider"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer"]\n')

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
                        "--force-plugins",
                        "plugins",
                        "graph",
                    ]
                )

            self.assertEqual(status, 0)
            text = output.getvalue()
            self.assertIn("Filesystem plugin load closure", text)
            self.assertIn("local/provider", text)
            self.assertIn("local/consumer", text)
            self.assertIn("configured", text)
            self.assertIn("auto-loaded", text)
            self.assertIn("requires_plugins", text)

    def test_cli_plugin_graph_json_includes_filesystem_dependency_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/provider", "provider", "provider")
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/provider"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer"]\n')

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
                        "--force-plugins",
                        "plugins",
                        "graph",
                        "--json",
                    ]
                )

            self.assertEqual(status, 0)
            closure = json.loads(output.getvalue())["filesystem_dependency_closure"]
            self.assertEqual(closure["requested"], ["local/consumer"])
            self.assertEqual(closure["auto_loaded"], ["local/provider"])
            self.assertEqual(closure["load_order"], ["local/provider", "local/consumer"])
            self.assertEqual(closure["auto_load_reasons"], {"local/provider": "requires_plugins"})

    def test_filesystem_config_rejects_dependency_chain_when_nested_dependency_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            provider = write_plugin(root, "local/provider", "provider", "provider")
            provider_marker = Path(tmp, "provider-imported")
            provider_plugin = provider / "plugin.py"
            provider_plugin.write_text(
                f"from pathlib import Path\nPath({str(provider_marker)!r}).touch()\n"
                + provider_plugin.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            provider_manifest = provider / "bywaf.plugin.toml"
            provider_manifest.write_text(
                provider_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/missing"]\n',
                ),
                encoding="utf-8",
            )
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_marker = Path(tmp, "consumer-imported")
            consumer_plugin = consumer / "plugin.py"
            consumer_plugin.write_text(
                f"from pathlib import Path\nPath({str(consumer_marker)!r}).touch()\n"
                + consumer_plugin.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/provider"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer"]\n')
            db_path = Path(tmp, "db.sqlite3")

            with self.assertRaisesRegex(ValueError, "local/provider: missing required plugin: local/missing"):
                make_runner(db_path, plugin_root=root, plugin_config=config, forced_plugins=True)

            events = EventStore(db_path).events_for_topic("plugin.dependency.auto_loaded")
            self.assertEqual(events, [])
            self.assertFalse(provider_marker.exists())
            self.assertFalse(consumer_marker.exists())

    def test_filesystem_config_rejects_missing_declared_plugin_dependency_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            consumer = write_plugin(root, "local/consumer", "consumer", "consumer")
            consumer_manifest = consumer / "bywaf.plugin.toml"
            consumer_manifest.write_text(
                consumer_manifest.read_text(encoding="utf-8").replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["local/missing"]\n',
                ),
                encoding="utf-8",
            )
            config = root / "plugins.toml"
            config.write_text('default_plugins = ["local/consumer"]\n')

            with self.assertRaisesRegex(ValueError, "missing required plugin: local/missing"):
                make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config, forced_plugins=True)

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
