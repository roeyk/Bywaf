"""Framework HTTP app tests for test framework requests.

Coverage focus: framework http app framework requests regression behavior.
"""

from pathlib import Path
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, new_shell_state, process_framework_requests
from bywaf.artifacts import artifact_store_for_db


class TestFrameworkRequestsTests(unittest.TestCase):
    """Groups regression coverage for framework HTTP app tests for test framework requests."""
    def test_framework_request_updates_prompt_and_records_audit_event(self):
        """Protect framework request updates prompt and records audit event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": "requested> "}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "requested> ")
            updated = runner.db.events_for_topic("shell.prompt.updated")[0]
            self.assertEqual(updated.payload["request_event_id"], request.id)

    def test_framework_request_denies_invalid_prompt_request(self):
        """Protect framework request denies invalid prompt request behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": ""}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "$Y$M$D $h:$m:$s $Z%F> ")
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_emits_console_alert(self):
        """Protect framework request emits console alert behavior from regressions."""
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
        """Protect new shell state ignores historical framework requests behavior from regressions."""
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
        """Protect framework request denies invalid console alert behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("framework.console.alert.requested", {"message": ""}, "plugin")
            process_framework_requests(runner, state)
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_emits_console_output(self):
        """Protect framework request emits console output behavior from regressions."""
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

    def test_framework_request_pages_file_without_tty(self):
        """Protect framework request pages file without tty behavior from regressions."""
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
        """Protect framework request page ignores pager keyboard interrupt behavior from regressions."""
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
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((4, 1))),
                patch("bywaf.pager.subprocess.run", side_effect=KeyboardInterrupt),
            ):
                process_framework_requests(runner, state)
            self.assertEqual(len(runner.db.events_for_topic("console.page")), 1)

    def test_framework_request_denies_background_file_page(self):
        """Protect framework request denies background file page behavior from regressions."""
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
        """Protect framework request runs external process behavior from regressions."""
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
            artifact = artifact_store_for_db(runner.db).list(command_run_id="run-1")[0]
            self.assertEqual(event.payload["request_event_id"], request.id)
            self.assertEqual(event.payload["stdout"], "hello\n")
            self.assertEqual(event.payload["returncode"], 0)
            self.assertEqual(event.payload["artifact_id"], artifact.artifact_id)
            self.assertIn("stdout:\nhello\n", artifact.body.decode())

    def test_framework_request_denies_invalid_process_argv(self):
        """Protect framework request denies invalid process argv behavior from regressions."""
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
        """Protect framework request skips already handled process request behavior from regressions."""
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
        """Protect framework request denies unhandled process stream request behavior from regressions."""
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
        """Protect framework request is processed once per shell state behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.db.publish("shell.prompt.requested", {"prompt": "once> "}, "test")
            process_framework_requests(runner, state)
            process_framework_requests(runner, state)
            self.assertEqual(len(runner.db.events_for_topic("shell.prompt.updated")), 1)


if __name__ == "__main__":
    unittest.main()
