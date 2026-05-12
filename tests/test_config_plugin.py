import unittest

from bywaf.config import Settings, default_settings
from bywaf.plugin import CommandContext, CommandSpec, OptionSpec
from bywaf.messages import Host, Progress
from bywaf.varstore import VarStore


class ConfigPluginTests(unittest.TestCase):
    def test_default_settings(self):
        settings = default_settings()
        self.assertIsInstance(settings, Settings)
        self.assertEqual(settings.database.as_posix(), ".bywaf/bywaf.sqlite3")
        self.assertEqual(settings.config.as_posix(), ".bywaf/config.json")
        self.assertEqual(settings.history.as_posix(), ".bywaf/history.bywaf")
        self.assertEqual(settings.plugin_dir.as_posix(), ".bywaf/plugins")
        self.assertEqual(settings.script_dir.as_posix(), ".bywaf/scripts")
        self.assertEqual(settings.database_dir.as_posix(), ".bywaf/db")
        self.assertEqual(settings.config_dir.as_posix(), ".bywaf/config")

    def test_option_spec_defaults(self):
        option = OptionSpec("ports", "ports to scan")
        self.assertEqual(option.choices, ())

    def test_command_spec_defaults(self):
        spec = CommandSpec("name", "description")
        self.assertEqual(spec.options, ())
        self.assertEqual(spec.emits, ())

    def test_command_context_metadata_default(self):
        context = CommandContext(db=None, source="test")
        self.assertEqual(context.metadata, {})

    def test_varstore_items_sorted(self):
        store = VarStore()
        store.set("b", 2)
        store.set("a", 1)
        self.assertEqual(store.items(), [("a", "1"), ("b", "2")])

    def test_host_message_json_round_trip(self):
        host = Host(run_id="1", host="127.0.0.1")
        self.assertEqual(Host.from_json(host.to_json()), host)

    def test_progress_percent(self):
        self.assertEqual(Progress(run_id="1", status="x", total=4, completed=1).percent, 25)


if __name__ == "__main__":
    unittest.main()
