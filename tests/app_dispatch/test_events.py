"""Tests for app events behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch events regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    dispatch_repl_line,
    make_runner,
)
from bywaf.event import Event

class AppDispatchTests(unittest.TestCase):
    """REPL-level tests for event, step, and shell-exec display behavior."""

    def test_events_defaults_to_tail_last_25(self):
        """Protect events defaults to tail last 25 behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            for number in range(30):
                runner.db.publish("topic", {"n": number}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events")
            text = output.getvalue()
            # The default events view is a tail, not a full database dump.
            self.assertNotIn("'n': 4", text)
            self.assertIn("'n': 5", text)
            self.assertIn("'n': 29", text)

    def test_events_tail_accepts_last_selector(self):
        """Protect events tail accepts last selector behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            for number in range(5):
                runner.db.publish("topic", {"n": number}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events tail last=2")
            text = output.getvalue()
            self.assertNotIn("'n': 2", text)
            self.assertIn("'n': 3", text)
            self.assertIn("'n': 4", text)

    def test_event_follow_once_reads_step_scope(self):
        """Protect event follow once reads step scope behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 80}, "portscanner", pipeline_id="p", command_run_id="r")
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner", pipeline_id="p", command_run_id="other")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event follow step=1 topic=port.open since=beginning once=true")

            text = output.getvalue()
            # step=1 resolves to the first command run in the database and
            # scopes follow output to that run.
            self.assertIn("following events; press Ctrl-C to stop", text)
            self.assertIn("192.0.2.10:80", text)
            self.assertNotIn("192.0.2.20", text)

    def test_event_follow_once_reads_job_scope(self):
        """Protect event follow once reads job scope behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="portscanner",
                values={},
            )
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 80}, "portscanner", pipeline_id="p", command_run_id="r")
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner", pipeline_id="other", command_run_id="other")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event follow job=1 topic=port.open since=beginning once=true")

            text = output.getvalue()
            # job=1 scopes the follow query through command_run metadata, so
            # events in unrelated pipelines stay hidden.
            self.assertIn("192.0.2.10:80", text)
            self.assertNotIn("192.0.2.20", text)

    def test_event_filters_topic_by_payload_host(self):
        """Protect event filters topic by payload host behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 80, "protocol": "tcp"}, "test")
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open host=192.0.2.20")
            text = output.getvalue()
            # Payload selectors use normalized topic renderers when available;
            # port.open is rendered as host:port/protocol.
            self.assertNotIn("192.0.2.10", text)
            self.assertIn("192.0.2.20:443/tcp", text)

    def test_event_filters_nested_host_and_sorts(self):
        """Protect event filters nested host and sorts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("finding.candidate", {"target": {"host": "192.0.2.20"}, "port": 443}, "test")
            runner.db.publish("finding.candidate", {"target": {"host": "192.0.2.10"}, "port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event finding.candidate host=192.0.2.10,192.0.2.20 sort=host")
            lines = [line for line in output.getvalue().splitlines() if "finding.candidate" in line]
            # Host selectors look through common nested payload locations such
            # as target.host, not only a top-level host field.
            self.assertIn("192.0.2.10", lines[0])
            self.assertIn("192.0.2.20", lines[1])

    def test_event_filters_support_include_exclude_and_network_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.168.50.10", "port": 80}, "test")
            runner.db.publish("port.open", {"host": "192.168.50.130", "port": 80}, "test")
            runner.db.publish("port.open", {"host": "192.168.51.20", "port": 443}, "test")
            runner.db.publish("port.open", {"host": "198.51.100.10", "port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(
                    runner,
                    "event port.open host=192.168.50.0/24,!192.168.50.1-128 port=80",
                )
            text = output.getvalue()
            # Include/exclude selectors are evaluated as a set expression: the
            # CIDR include is narrowed by the explicit range exclusion.
            self.assertNotIn("192.168.50.10", text)
            self.assertIn("192.168.50.130:80", text)
            self.assertNotIn("192.168.51.20", text)
            self.assertNotIn("198.51.100.10", text)

    def test_step_without_id_lists_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step")
            text = output.getvalue()
            self.assertIn("no steps", text)

    def test_exec_without_shell_command_prints_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "exec")
            text = output.getvalue()
            self.assertIn("Command: exec <argv...>", text)
            self.assertIn("Usage:   exec <argv...>", text)

    def test_exec_runs_argv_without_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            completed = subprocess.CompletedProcess(["echo", "hello world"], 0)
            with patch("bywaf.repl.command.exec.subprocess.run", return_value=completed) as run:
                dispatch_repl_line(runner, "exec echo 'hello world'")

            # exec deliberately avoids a shell; quoted tokens are parsed by the
            # REPL and passed as argv directly.
            run.assert_called_once_with(["echo", "hello world"], check=False)
            events = runner.events.events_matching(topic="shell.exec.completed")
            self.assertEqual(events[-1].payload["argv"], ["echo", "hello world"])

    def test_foreground_commandlet_does_not_print_completion_footer(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
            self.assertNotIn("done:", output.getvalue())

    def test_background_commandlet_does_not_print_completion_footer(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            event = Event.new(
                "job.requested",
                {"job_id": 1, "command": "hostscanner 127.0.0.1 &"},
                "runner",
            )
            with patch.object(runner, "start_background", return_value=event):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "hostscanner 127.0.0.1 &")
            self.assertNotIn("done:", output.getvalue())

    def test_step_inspects_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step 1")
            text = output.getvalue()
            # Step inspection merges captured variables and emitted events into
            # one operator-facing view.
            self.assertIn("Variables", text)
            self.assertIn("test.marker=1", text)
            self.assertIn("host.found 127.0.0.1", text)

    def test_step_show_summarizes_captured_console_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="p",
                command_run_id="r",
                commandlet="step",
                values={"display/style.host": "green", "operator.note": "manual check"},
            )
            runner.db.publish(
                "framework.console.output.requested",
                {
                    "source": "step",
                    "text": "STEP  STATUS\n----  ------\n1     completed\n2     completed",
                },
                "step",
                pipeline_id="p",
                command_run_id="r",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step 1")

            text = output.getvalue()
            # Captured console blocks are summarized so one verbose command
            # does not overwhelm the step detail view.
            self.assertIn("operator.note=manual check", text)
            self.assertNotIn("display/style.host", text)
            self.assertIn("text=STEP  STATUS", text)
            self.assertNotIn("2     completed", text)

    def test_step_show_points_to_job_when_completion_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner host=192.0.2.0/24", 123, "stale")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"discovery/hostscanner.targets": "192.0.2.0/24"},
            )
            runner.db.publish(
                "command.run.started",
                {"status": "started"},
                "framework",
                pipeline_id="p",
                command_run_id="r",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step 1")

            text = output.getvalue()
            self.assertIn(f"inspect further with: job {job_id}; event step=1", text)
            self.assertIn(f"No step completion event was recorded; inspect owning job with `job {job_id}`.", text)

    def test_events_colors_event_ids_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.events.color", "always")
            event = runner.db.publish("plugin.progress.completed", {"commandlet": "hostscanner", "n": 1}, "hostscanner")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events last=1")
            text = output.getvalue()
            self.assertIn(f"\x1b[94m{event.id}\x1b[0m:", text)
            self.assertIn("\x1b[1;33mhostscanner\x1b[0m", text)

    def test_events_use_semantic_display_roles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.host", "bold green")
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[1;32m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_accept_escaped_hex_display_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, r"set display/style.host=\#00ff00")
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[38;2;0;255;0m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_accept_quoted_hex_display_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, 'set display/style.host="#00ff00"')
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[38;2;0;255;0m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_style_quoted_string_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.string", "bold yellow")
            runner.db.publish("example.topic", {"message": "quoted value"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event example.topic")
            self.assertIn("\x1b[1;33m'quoted value'\x1b[0m", output.getvalue())

    def test_event_id_prints_event_runtime_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.finish_job(job_id, "failed")
            event = runner.db.publish(
                "job.failed",
                {"job_id": job_id, "command": "hostscanner 127.0.0.1", "error": "boom"},
                "runner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event {event.id}")
            text = output.getvalue()
            self.assertIn(f"Event ID: {event.id}", text)
            self.assertIn("Topic: job.failed", text)
            self.assertIn("Source: runner", text)
            self.assertIn("Created: ", text)
            created = text.split("Created: ", 1)[1].splitlines()[0]
            self.assertRegex(created, r"\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("Job:", text)
            self.assertIn("Commandlet: hostscanner", text)
            self.assertIn("Command: hostscanner 127.0.0.1", text)
            self.assertIn("error: boom", text)

    def test_event_id_reports_unknown_event_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event 999")
            self.assertIn("error: unknown event: 999", output.getvalue())

    def test_event_id_colors_detail_keys_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.events.color", "always")
            runner.registry.varstore.set("display.events.key-color", "green")
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.finish_job(job_id, "failed")
            event = runner.db.publish(
                "job.failed",
                {"job_id": job_id, "commandlet": "hostscanner", "error": "boom"},
                "runner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event {event.id}")
            text = output.getvalue()
            self.assertIn(f"\x1b[33mEvent ID\x1b[0m: \x1b[94m{event.id}\x1b[0m", text)
            self.assertIn("\x1b[32mTopic\x1b[0m: job.failed", text)
            self.assertIn("\x1b[32mCommandlet\x1b[0m: \x1b[1;33mhostscanner\x1b[0m", text)
            self.assertIn("\x1b[33mPayload\x1b[0m:", text)
            self.assertIn("  \x1b[32mcommandlet\x1b[0m: \x1b[1;33mhostscanner\x1b[0m", text)
            self.assertIn("  \x1b[32merror\x1b[0m: boom", text)


if __name__ == "__main__":
    unittest.main()
