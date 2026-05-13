from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from bywaf.app import (
    ShellState,
    friendly_error,
    make_runner,
    process_framework_requests,
    render_prompt,
)
from bywaf.events import Event
from bywaf.plugins.http.http_headers import HttpHeaders



class FrameworkHttpAppTests(unittest.TestCase):
    def test_framework_request_updates_prompt_and_records_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": "requested> "}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "requested> ")
            updated = runner.db.events_for_topic("shell.prompt.updated")[0]
            self.assertEqual(updated.payload["request_event_id"], request.id)

    def test_framework_request_denies_invalid_prompt_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": ""}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "bywaf> ")
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_emits_console_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.console.alert.requested",
                {"message": "hello", "source": "plugin"},
                "plugin",
                command_run_id="run-1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                process_framework_requests(runner, state)
            alert = runner.db.events_for_topic("console.alert")[0]
            self.assertEqual(alert.payload["request_event_id"], request.id)
            self.assertEqual(output.getvalue(), "plugin <run-1>: hello\n")

    def test_framework_request_denies_invalid_console_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("framework.console.alert.requested", {"message": ""}, "plugin")
            process_framework_requests(runner, state)
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_emits_console_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.console.output.requested",
                {"text": "hello", "end": ""},
                "plugin",
                command_run_id="run-1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                process_framework_requests(runner, state)
            event = runner.db.events_for_topic("console.output")[0]
            self.assertEqual(event.payload["request_event_id"], request.id)
            self.assertEqual(output.getvalue(), "hello")

    def test_framework_request_is_processed_once_per_shell_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.db.publish("shell.prompt.requested", {"prompt": "once> "}, "test")
            process_framework_requests(runner, state)
            process_framework_requests(runner, state)
            self.assertEqual(len(runner.db.events_for_topic("shell.prompt.updated")), 1)

    def test_render_prompt_replaces_time_placeholder(self):
        self.assertNotIn("%T", render_prompt("%T> "))

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
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/external\n")
            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config)
            self.assertIn("external", runner.registry.names())

    def test_friendly_error_strips_keyerror_quotes(self):
        self.assertEqual(friendly_error(KeyError("unknown commandlet: x")), "unknown commandlet: x")

    def test_http_headers_targets_from_arg(self):
        targets = HttpHeaders().targets("example.test", None, False, [])
        self.assertEqual(targets, [("example.test", 80, False)])

    def test_http_headers_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpHeaders().targets(None, None, False, [event])
        self.assertEqual(targets, [("127.0.0.1", 443, True)])


class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
