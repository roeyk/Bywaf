"""Tests for framework http app behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import sys
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    friendly_error,
    make_runner,
    new_shell_state,
    process_framework_requests,
    render_prompt,
)
from bywaf.events import Event
from bywaf.plugin import CommandContext
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
            self.assertEqual(state.prompt_pattern, "$Y$M$D $h:$m:$s $Z> ")
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

    def test_new_shell_state_ignores_historical_framework_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "framework.console.alert.requested",
                {"message": "old", "source": "plugin"},
                "plugin",
                command_run_id="old-run",
            )
            state = new_shell_state(runner)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                process_framework_requests(runner, state)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(runner.db.events_for_topic("console.alert"), [])

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

    def test_context_records_declared_capability_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("framework.console.output",)},
            )
            context.output("hello")
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "framework.console.output")
            self.assertTrue(used.payload["declared"])
            self.assertEqual(runner.db.events_for_topic("plugin.capability.missing"), [])

    def test_context_records_missing_capability_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin")
            context.output("hello")
            missing = runner.db.events_for_topic("plugin.capability.missing")[0]
            self.assertEqual(missing.payload["capability"], "framework.console.output")
            self.assertFalse(missing.payload["declared"])

    def test_context_events_publish_uses_scope_and_audits_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={
                    "pipeline_id": "pipeline-1",
                    "command_run_id": "run-1",
                    "capabilities": ("db.write:test.topic",),
                },
            )
            event = context.events.publish("test.topic", {"ok": True})
            self.assertEqual(event.pipeline_id, "pipeline-1")
            self.assertEqual(event.command_run_id, "run-1")
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.write:test.topic")
            self.assertTrue(used.payload["declared"])

    def test_context_events_fetch_audits_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("test.topic", {"ok": True}, "test")
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.read:test.topic",)},
            )
            events = context.events.fetch(("test.topic",))
            self.assertEqual(events[0].payload["ok"], True)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.read:test.topic")
            self.assertTrue(used.payload["declared"])

    def test_context_events_does_not_audit_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.write:test.topic",)},
            )
            context.events.publish("test.topic", {"ok": True})
            capabilities = [
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            ]
            self.assertEqual(capabilities, ["db.write:test.topic"])

    def test_narrow_store_accessors_do_not_audit_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin")
            self.assertIs(context.event_store(), runner.db)
            self.assertIs(context.runtime_store(), runner.db)
            self.assertEqual(runner.db.events_for_topic("plugin.capability.used"), [])

    def test_maintenance_store_accessor_audits_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.raw",)},
            )
            self.assertIs(context.maintenance_store(), runner.db)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.raw")
            self.assertTrue(used.payload["declared"])

    def test_raw_context_db_access_audits_db_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.raw",)},
            )
            self.assertIsNotNone(context.db)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.raw")
            self.assertTrue(used.payload["declared"])

    def test_framework_request_pages_file_without_tty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("hello\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.file.page.requested",
                {"path": str(path), "source": "less"},
                "less",
                command_run_id="run-1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                process_framework_requests(runner, state)
            event = runner.db.events_for_topic("console.page")[0]
            self.assertEqual(event.payload["request_event_id"], request.id)
            self.assertEqual(output.getvalue(), "hello\n")

    def test_framework_request_page_ignores_pager_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("hello\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.db.publish(
                "framework.file.page.requested",
                {"path": str(path), "source": "less"},
                "less",
            )
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.subprocess.run", side_effect=KeyboardInterrupt),
            ):
                process_framework_requests(runner, state)
            self.assertEqual(len(runner.db.events_for_topic("console.page")), 1)

    def test_framework_request_denies_background_file_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("hello\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.file.page.requested",
                {"path": str(path), "background": True},
                "less",
            )
            process_framework_requests(runner, state)
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_runs_external_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.process.run.requested",
                {"argv": [sys.executable, "-c", "print('hello')"], "source": "plugin"},
                "plugin",
                command_run_id="run-1",
            )
            process_framework_requests(runner, state)
            event = runner.db.events_for_topic("process.run")[0]
            self.assertEqual(event.payload["request_event_id"], request.id)
            self.assertEqual(event.payload["stdout"], "hello\n")
            self.assertEqual(event.payload["returncode"], 0)

    def test_framework_request_denies_invalid_process_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.process.run.requested",
                {"argv": "echo hello"},
                "plugin",
            )
            process_framework_requests(runner, state)
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_skips_already_handled_process_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.db.publish(
                "framework.process.run.requested",
                {"argv": [sys.executable, "-c", "print('hello')"], "handled": True},
                "plugin",
            )
            process_framework_requests(runner, state)
            self.assertEqual(runner.db.events_for_topic("process.run"), [])

    def test_framework_request_denies_unhandled_process_stream_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish(
                "framework.process.stream.requested",
                {"argv": [sys.executable, "-c", "print('hello')"]},
                "plugin",
            )
            process_framework_requests(runner, state)
            denied = runner.db.events_for_topic("framework.request.denied")[0]
        self.assertEqual(denied.payload["request_event_id"], request.id)

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

    def test_render_prompt_replaces_dollar_placeholders(self):
        rendered = render_prompt("$u $Y-$M-$D $h:$m:$s $Z> ")
        for placeholder in ("$u", "$Y", "$M", "$D", "$h", "$m", "$s", "$Z"):
            self.assertNotIn(placeholder, rendered)
        self.assertIn(">", rendered)

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

    def test_http_headers_targets_from_arg(self):
        targets = HttpHeaders().targets("example.test", None, False, [])
        self.assertEqual(targets, [("example.test", 80, False)])

    def test_http_headers_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpHeaders().targets(None, None, False, [event])
        self.assertEqual(targets, [("127.0.0.1", 443, True)])

    def test_http_headers_promotes_missing_security_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.http_headers.detect.http.client.HTTPSConnection", FakeHttpConnection):
                runner.execute("http_headers --ssl true example.test")

            candidates = runner.db.events_for_topic("finding.candidate")
            titles = {event.payload["title"] for event in candidates}
            self.assertEqual(
                titles,
                {"Missing HTTP Strict Transport Security", "Missing X-Content-Type-Options"},
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))


class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakeHttpResponse:
    status = 200
    headers = {"Server": "example"}


class FakeHttpConnection:
    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path):
        self.method = method
        self.path = path

    def getresponse(self):
        return FakeHttpResponse()

    def close(self):
        return None


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
