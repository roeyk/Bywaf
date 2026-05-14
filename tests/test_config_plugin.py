import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from bywaf.config import Settings, default_settings
from bywaf.db import EventStore
from bywaf.plugin import (
    ArgumentSpec,
    CommandContext,
    CommandSpec,
    CompletionSpec,
    OptionSpec,
    argument,
    commandlet,
    format_table,
    normalize_argv,
    option,
)
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

    def test_commandlet_decorators_build_spec(self):
        @commandlet(
            name="hello",
            description="say hello",
            usage="hello [name]",
            examples=("hello world",),
            emits=("hello.greeting",),
            capabilities=("framework.console.output",),
        )
        @option("timeout", "timeout seconds", default="5")
        @option("uppercase", "uppercase output", default="false", choices=("true", "false"))
        @argument("suffix", "suffix", required=False)
        @argument("name", "name to greet", required=False, completion="plugin")
        class Hello:
            pass

        spec = getattr(Hello, "spec")
        self.assertEqual(spec.name, "hello")
        self.assertEqual(spec.arguments[0].name, "suffix")
        self.assertEqual(spec.arguments[1].name, "name")
        self.assertFalse(spec.arguments[1].required)
        self.assertEqual(spec.arguments[1].completion, CompletionSpec("plugin"))
        self.assertEqual(spec.options[0].name, "timeout")
        self.assertEqual(spec.options[1].name, "uppercase")
        self.assertEqual(spec.options[1].choices, ("true", "false"))
        self.assertEqual(spec.emits, ("hello.greeting",))
        self.assertEqual(spec.capabilities, ("framework.console.output",))

    def test_command_context_metadata_default(self):
        context = CommandContext(db=None, source="test")
        self.assertEqual(context.metadata, {})

    def test_command_context_exposes_scoped_vars(self):
        context = CommandContext(db=None, source="test")
        context.vars.set("value", "abc")
        self.assertEqual(context.vars.get("value"), "abc")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other.value")

    def test_command_context_vars_prefer_run_snapshot(self):
        store = VarStore()
        store.set("test.value", "session")
        store.set("global.proxy", "session-proxy")
        context = CommandContext(
            db=None,
            source="test",
            _varstore=store,
            metadata={
                "run_vars": {
                    "test.value": "run",
                    "global.proxy": "run-proxy",
                }
            },
        )
        self.assertEqual(context.vars.get("value"), "run")
        self.assertEqual(context.vars.get_global("proxy"), "run-proxy")

    def test_command_context_alert_prints_without_database(self):
        context = CommandContext(db=None, source="test", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            context.alert("hello")
        self.assertEqual(output.getvalue(), "test <run-1>: hello\n")

    def test_command_context_alert_requests_framework_event_when_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"command_run_id": "run-1"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                context.alert("hello", silent=True)
            requests = db.events_for_topic("framework.console.alert.requested")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(requests[0].payload["message"], "hello")
        self.assertTrue(requests[0].payload["silent"])
        self.assertEqual(requests[0].command_run_id, "run-1")

    def test_command_context_output_requests_framework_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"command_run_id": "run-1"})
            context.output("hello", end="")
            requests = db.events_for_topic("framework.console.output.requested")
        self.assertEqual(requests[0].payload["text"], "hello")
        self.assertEqual(requests[0].payload["end"], "")
        self.assertEqual(requests[0].command_run_id, "run-1")

    def test_command_context_process_run_records_request_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("process.run",),
                },
            )
            result = context.process.run([sys.executable, "-c", "print('hello')"])
            requests = db.events_for_topic("framework.process.run.requested")
            results = db.events_for_topic("process.run")
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "hello\n")
        self.assertEqual(requests[0].payload["argv"], [sys.executable, "-c", "print('hello')"])
        self.assertEqual(results[0].payload["returncode"], 0)
        self.assertEqual(results[0].payload["request_event_id"], requests[0].id)

    def test_command_context_process_run_audits_missing_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test")
            context.process.run([sys.executable, "-c", "print('hello')"])
            missing = db.events_for_topic("plugin.capability.missing")
        self.assertEqual(missing[0].payload["capability"], "process.run")

    def test_command_context_process_stream_records_incremental_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={"capabilities": ("process.run",)},
            )
            chunks = list(
                context.process.stream(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        "import sys; print('out'); print('err', file=sys.stderr)",
                    ]
                )
            )
            started = db.events_for_topic("process.started")
            stdout = db.events_for_topic("process.stdout")
            stderr = db.events_for_topic("process.stderr")
            exited = db.events_for_topic("process.exited")
        self.assertEqual([chunk.stream for chunk in chunks], ["stdout", "stderr"])
        self.assertEqual(started[0].payload["argv"][0], sys.executable)
        self.assertEqual(stdout[0].payload["text"], "out\n")
        self.assertEqual(stderr[0].payload["text"], "err\n")
        self.assertEqual(exited[0].payload["returncode"], 0)

    def test_normalize_argv_rejects_shell_string(self):
        with self.assertRaisesRegex(TypeError, "sequence of strings"):
            normalize_argv("echo hello")

    def test_normalize_argv_rejects_empty_argv(self):
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            normalize_argv([])

    def test_format_table_aligns_mapping_rows(self):
        lines = format_table([{"name": "one", "value": 1}], ("name", "value"))
        self.assertEqual(lines, ["name  value", "----  -----", "one   1    "])

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
