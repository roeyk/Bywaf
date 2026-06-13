"""Tests for app runtime lists behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch runtime lists regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    make_runner,
)
from bywaf.plugins.network.nmap.backend import NmapPort



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app runtime lists behavior."""
    def test_dispatch_steps_lists_command_runs(self):
        """Protect dispatch steps lists command runs behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.publish(
                "artifact.attached",
                {"artifact_id": "artifact-1", "job_id": job_id},
                "framework",
                pipeline_id="p",
                command_run_id="r",
            )
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step")
            text = output.getvalue()
            self.assertIn("STEP", text)
            self.assertIn("ART", text)
            self.assertRegex(text, r"\n1\s+active/running\s+1\s+hostscanner\s+2\s+1\s+")
            self.assertEqual(text.count("hostscanner"), 1)

    def test_runtime_lists_filter_by_host_payload(self):
        """Protect runtime lists filter by host payload behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_one = runner.db.record_job("hostscanner 192.0.2.10", 123, "running")
            job_two = runner.db.record_job("hostscanner 192.0.2.20", 124, "running")
            runner.db.record_command_run_vars(
                job_id=job_one,
                pipeline_id="pipe-a",
                command_run_id="step-a",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.record_command_run_vars(
                job_id=job_two,
                pipeline_id="pipe-b",
                command_run_id="step-b",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("host.found", {"host": "192.0.2.10"}, "hostscanner", pipeline_id="pipe-a", command_run_id="step-a")
            runner.db.publish("host.found", {"host": "192.0.2.20"}, "hostscanner", pipeline_id="pipe-b", command_run_id="step-b")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")
            text = output.getvalue()
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)
            self.assertNotIn("pipe-a", text)
            self.assertNotIn("step-a", text)

    def test_runtime_filter_lists_include_finished_scopes(self):
        """Protect runtime filter lists include finished scopes behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-done",
                command_run_id="step-done",
                commandlet="portscanner",
                values={"network/portscanner.host": "192.0.2.20"},
            )
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner", pipeline_id="pipe-done", command_run_id="step-done")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")
            text = output.getvalue()
            self.assertIn("portscanner", text)
            self.assertIn("host=192.0.2.20", text)
            self.assertIn("PIPELINE", text)
            self.assertIn("STEP", text)

    def test_runtime_filters_match_foreground_portscanner_events(self):
        """Protect runtime filters match foreground portscanner events behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("192.0.2.10", 80, "tcp", "open", "http")],
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "network/portscanner host=192.0.2.10 port=80", state)
                    dispatch_repl_line(runner, "job host=192.0.2.10", state)
                    dispatch_repl_line(runner, "step host=192.0.2.10", state)
                    dispatch_repl_line(runner, "pipeline host=192.0.2.10", state)
            text = output.getvalue()
            self.assertIn("network/portscanner", text)
            self.assertIn("host=192.0.2", text)
            self.assertIn("STEP", text)
            self.assertIn("PIPELINE", text)

    def test_ports_defaults_to_latest_productive_portscanner_job(self):
        """Protect ports defaults to latest productive portscanner job behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.10"},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp", "service": "http", "reason": "syn-ack"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            new_job = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=new_job,
                pipeline_id="new-pipeline",
                command_run_id="new-step",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.20"},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https", "reason": "syn-ack"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports")
            text = output.getvalue()
            self.assertIn(f"latest portscanner job={new_job}", text)
            self.assertIn("grouped by host ascending (use sort=-host to sort descending)", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)

    def test_ports_all_true_shows_historical_port_events(self):
        """Protect ports all true shows historical port events behavior from regressions."""
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
            new_job = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=new_job,
                pipeline_id="new-pipeline",
                command_run_id="new-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports all=true sort=event")
                dispatch_repl_line(runner, "ports all=true sort=-event")
            text = output.getvalue()
            self.assertIn("all port.open events", text)
            self.assertIn("sorted by event ascending (use sort=-event to sort descending)", text)
            self.assertIn("sorted by event descending (use sort=event to sort ascending)", text)
            self.assertIn("192.0.2.10", text)
            self.assertIn("192.0.2.20", text)

    def test_ports_filters_latest_scan_by_host_and_port(self):
        """Protect ports filters latest scan by host and port behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner host=192.0.2.0/24 port=80,443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline",
                command_run_id="step",
                commandlet="network/portscanner",
                values={},
            )
            for host, port in (("192.0.2.10", 80), ("192.0.2.20", 443), ("192.0.2.30", 22)):
                runner.db.publish(
                    "port.open",
                    {"host": host, "port": port, "protocol": "tcp"},
                    "portscanner",
                    pipeline_id="pipeline",
                    command_run_id="step",
                )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports host=192.0.2.0/24,!192.0.2.1-15 port=443")
            text = output.getvalue()
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)
            self.assertNotIn("192.0.2.30", text)


if __name__ == "__main__":
    unittest.main()
