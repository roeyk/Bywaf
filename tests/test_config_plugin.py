import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from bywaf.config import Settings, default_settings
from bywaf.db import EventStore
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, CompletionSpec, OptionSpec
from bywaf.messages import Host, Progress
from bywaf.varstore import ScopedVarStore, VarStore


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
        self.assertEqual(spec.arguments, ())
        self.assertEqual(spec.emits, ())

    def test_argument_spec_defaults(self):
        argument = ArgumentSpec("path")
        self.assertTrue(argument.required)
        self.assertEqual(argument.completion, CompletionSpec())

    def test_command_context_metadata_default(self):
        context = CommandContext(db=None, source="test")
        self.assertEqual(context.metadata, {})

    def test_command_context_exposes_scoped_vars(self):
        context = CommandContext(db=None, source="test")
        context.vars.set("value", "abc")
        self.assertEqual(context.vars.get("value"), "abc")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other.value")

    def test_command_context_alert_prints_without_database(self):
        context = CommandContext(db=None, source="test", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            context.alert("hello")
        self.assertEqual(output.getvalue(), "test <run-1>: hello\n")

    def test_command_context_alert_records_event_when_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"command_run_id": "run-1"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                context.alert("hello", silent=True)
            alerts = db.events_for_topic("console.alert")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(alerts[0].payload["message"], "hello")
        self.assertEqual(alerts[0].command_run_id, "run-1")

    def test_scoped_varstore_reads_only_its_namespace(self):
        store = VarStore()
        store.set("one.secret", "a")
        store.set("two.secret", "b")
        one = ScopedVarStore(store, "one")
        self.assertEqual(one.get("secret"), "a")
        self.assertNotEqual(one.get("secret"), "b")

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
