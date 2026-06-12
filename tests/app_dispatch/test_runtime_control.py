"""Tests for app runtime control behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch runtime control regression behavior.
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
    process_framework_requests,
)



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app runtime control behavior."""
    def test_job_cancel_records_soft_cancellation(self):
        """Protect job cancel records soft cancellation behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"job cancel {job_id}")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"cancel requested for job {job_id}", output.getvalue())

    def test_pause_resume_stop_commands_record_job_state(self):
        """Protect pause resume stop commands record job state behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"pause job={job_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"resume --listonly job={job_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"stop job={job_id}")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())
            self.assertIn(f"queued resume actions for job {job_id}", output.getvalue())
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_pause_resume_stop_commands_accept_step_selector(self):
        """Protect pause resume stop commands accept step selector behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="portscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("pause step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume --listonly step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume step=run-1")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())
            self.assertIn("run.pause.requested step=run-1", output.getvalue())
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "running")

    def test_signal_records_plugin_scoped_live_control_request(self):
        """Protect signal records plugin scoped live control request behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("signal step=run-1 prune targets=192.168.1.0/24 reason=user-request")
                process_framework_requests(runner, ShellState())
            signal_event = runner.db.events_for_topic("runtime.signal.requested")[0]
            self.assertEqual(signal_event.command_run_id, "run-1")
            self.assertEqual(signal_event.payload["target_type"], "run")
            self.assertEqual(signal_event.payload["action"], "prune")
            self.assertEqual(signal_event.payload["args"]["targets"], "192.168.1.0/24")
            self.assertIn("signal requested for step=run-1 action=prune mode=soft", output.getvalue())

    def test_signal_pause_applies_framework_control(self):
        """Protect signal pause applies framework control behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"signal job={job_id} pause")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.events_for_topic("runtime.signal.requested")[0].payload["action"], "pause")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "pausing")
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())

    def test_runtime_control_uses_narrow_store_access(self):
        """Protect runtime control uses narrow store access behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"pause job={job_id}")
                process_framework_requests(runner, ShellState())
            capabilities = {
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            }
            self.assertIn("framework.job.control", capabilities)
            self.assertNotIn("db.raw", capabilities)

    def test_signal_accepts_job_and_run_serials_but_rejects_pipeline_serials(self):
        """Protect signal accepts job and run serials but rejects pipeline serials behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            job_serial = runner.db.job_serial(job_id)
            self.assertIsNotNone(job_serial)
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-serial",
                command_run_id="run-serial",
                commandlet="portscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"signal serial={job_serial} mute")
                process_framework_requests(runner, ShellState())
                runner.execute("signal serial=run-serial verbosity level=debug")
                process_framework_requests(runner, ShellState())
                dispatch_repl_line(runner, "signal serial=pipeline-serial mute")
            events = runner.db.events_for_topic("runtime.signal.requested")
            self.assertEqual(events[0].payload["target_type"], "job")
            self.assertEqual(events[0].payload["target_id"], str(job_id))
            self.assertEqual(events[1].payload["target_type"], "run")
            self.assertEqual(events[1].payload["target_id"], "run-serial")
            self.assertIn("error: signal serial= must resolve to a job or run, not a pipeline", output.getvalue())

    def test_job_end_defaults_to_cooperative_cancel(self):
        """Protect job end defaults to cooperative cancel behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job end {job_id}")
            kill.assert_not_called()
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_job_kill_hard_sends_kill(self):
        """Protect job kill hard sends kill behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job kill --hard {job_id}")
            self.assertEqual(kill.call_args.args[1].name, "SIGKILL")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "killed")

    def test_pipeline_cancel_records_soft_cancellation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("pipeline", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("pipeline cancel pipe-1")
                process_framework_requests(runner, ShellState())
            self.assertTrue(runner.db.cancellation_requested(pipeline_id="pipe-1"))
            self.assertIn("cancel requested for pipeline pipe-1", output.getvalue())

    def test_pipeline_kill_defaults_to_cooperative_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("pipeline", 99999, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("pipeline kill pipe-1")
            kill.assert_not_called()
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_convenience_end_and_kill_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"end job={job_id}")
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"kill --hard job={job_id}")
            self.assertEqual(kill.call_args.args[1].name, "SIGKILL")


if __name__ == "__main__":
    unittest.main()
