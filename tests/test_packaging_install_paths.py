from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from bywaf.app import main, make_runner


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
    (plugin_dir / "defaults.json").write_text('{"origin": "' + source + '"}')
    return plugin_dir


class PackagingInstallPathTests(unittest.TestCase):
    def test_user_local_shaped_plugin_root_loads_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp, "home", "alice")
            root = home / ".bywaf" / "plugins"
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.yaml"
            config.write_text("default_plugins:\n  - local/userprobe\n")

            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config)

            self.assertIn("userprobe", runner.registry.names())
            self.assertEqual(runner.registry.varstore.get("userprobe.origin"), "user-local")

    def test_system_wide_shaped_plugin_root_loads_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "usr", "share", "bywaf", "plugins")
            write_plugin(root, "site/systemprobe", "systemprobe", "system-wide")
            config = root / "plugins.yaml"
            config.write_text("default_plugins:\n  - site/systemprobe\n")

            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config)

            self.assertIn("systemprobe", runner.registry.names())
            self.assertEqual(runner.registry.varstore.get("systemprobe.origin"), "system-wide")

    def test_cli_run_uses_explicit_plugin_root_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "home", "alice", ".bywaf", "plugins")
            write_plugin(root, "local/userprobe", "userprobe", "user-local")
            config = root / "plugins.yaml"
            config.write_text("default_plugins:\n  - local/userprobe\n")

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
                        "run",
                        "userprobe",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertIn("'source': 'user-local'", output.getvalue())


if __name__ == "__main__":
    unittest.main()
