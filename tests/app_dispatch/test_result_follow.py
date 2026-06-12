"""Tests for app result follow behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch result follow regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest

from bywaf.app import (
    dispatch_repl_line,
    make_runner,
)


class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app result follow behavior."""
    def test_results_passes_sort_to_embedded_ports_view(self):
        """Protect results passes sort to embedded ports view behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results sort=port")

            text = output.getvalue()
            self.assertIn("Equivalent command: ports job=1 sort=port", text)
            self.assertIn("grouped by port ascending", text)

    def test_results_follow_once_renders_current_results(self):
        """Protect results follow once renders current results behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results --follow once=true interval=0.01")

            text = output.getvalue()
            self.assertIn("following results; press Ctrl-C to stop", text)
            self.assertIn("Results: latest job=1", text)
            self.assertIn("192.0.2.20", text)

    def test_result_follow_alias_uses_results_follow(self):
        """Protect result follow alias uses results follow behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "result --follow once=true interval=0.01")

            text = output.getvalue()
            self.assertIn("following results; press Ctrl-C to stop", text)
            self.assertIn("no results", text)

    def test_results_mentions_active_work_when_empty(self):
        """Protect results mentions active work when empty behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.record_job("hostscanner host=192.0.2.0/24 & | portscanner", 123, "running")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("no results yet; active work is still running", text)
            self.assertIn("hostscanner host=192.0.2.0/24 & | portscanner", text)
            self.assertIn("job 2", text)
            self.assertNotIn("192.0.2.10", text)

    def test_results_does_not_fall_back_when_latest_work_found_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("no results", text)
            self.assertNotIn("192.0.2.10", text)


if __name__ == "__main__":
    unittest.main()
