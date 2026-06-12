"""Framework HTTP app tests for test app helpers."""

from pathlib import Path
import tempfile
import unittest

from bywaf.app import friendly_error, make_runner, render_prompt


class TestAppHelpersTests(unittest.TestCase):
    """Groups regression coverage for framework HTTP app tests for test app helpers."""
    def test_render_prompt_replaces_time_placeholder(self):
        self.assertNotIn("%T", render_prompt("%T> "))

    def test_render_prompt_replaces_dollar_placeholders(self):
        rendered = render_prompt("$u $Y-$M-$D $h:$m:$s $Z> ")
        for placeholder in ("$u", "$Y", "$M", "$D", "$h", "$m", "$s", "$Z"):
            self.assertNotIn(placeholder, rendered)
        self.assertIn(">", rendered)

    def test_render_prompt_replaces_focus_placeholders(self):
        rendered = render_prompt("%p|%c|%P|%F> ", active_context="http/repo_exposure/git_expose_check")
        self.assertEqual(rendered, "http/repo_exposure|git_expose_check|http/repo_exposure/git_expose_check| http/repo_exposure/git_expose_check> ")
        self.assertEqual(render_prompt("%F> "), "> ")

    def test_make_runner_loads_external_plugin_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "external"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class External:\n"
                "    spec = CommandSpec('external', 'external plugin', emits=('external.event',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'external': True}\n"
                "def plugin():\n"
                "    return External()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "native = true\n\n"
                "[[commandlets]]\n"
                'name = "external"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/external\n")
            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config, forced_plugins=True)
            self.assertIn("external", runner.registry.names())

    def test_friendly_error_strips_keyerror_quotes(self):
        self.assertEqual(friendly_error(KeyError("unknown commandlet: x")), "unknown commandlet: x")


if __name__ == "__main__":
    unittest.main()
