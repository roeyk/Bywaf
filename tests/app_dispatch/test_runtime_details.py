"""Tests for app runtime details behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch runtime details regression behavior.
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
    """Groups regression coverage for app runtime details behavior."""
    def test_info_shows_active_runtime_counts(self):
        """Protect info shows active runtime counts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "info")
            text = output.getvalue()
            self.assertIn("Jobs (1)", text)
            self.assertIn("Pipelines (1)", text)
            self.assertIn("Steps (1)", text)
            self.assertIn("ART", text)

    def test_runtime_names_display_in_listings(self):
        """Protect runtime names display in listings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("runtime.name.assigned", {"target_type": "run", "target_id": "r", "name": "run name"}, "framework", command_run_id="r")
            runner.db.publish("runtime.name.assigned", {"target_type": "pipeline", "target_id": "p", "name": "pipeline name"}, "framework", pipeline_id="p")
            runner.db.publish("runtime.name.assigned", {"target_type": "job", "target_id": str(job_id), "name": "job name"}, "framework")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step")
                dispatch_repl_line(runner, "pipeline")
                dispatch_repl_line(runner, "job")
                dispatch_repl_line(runner, f"event job={job_id}")
                dispatch_repl_line(runner, "job 1")
                dispatch_repl_line(runner, "pipeline 1")
            text = output.getvalue()
            self.assertIn("run name", text)
            self.assertIn("pipeline name", text)
            self.assertIn("job name", text)
            self.assertIn("commandlet=hostscanner", text)
            self.assertIn("args=127.0.0.1", text)
            self.assertIn("ART", text)

    def test_job_show_includes_recorded_commandlet_arguments(self):
        """Protect job show includes recorded commandlet arguments behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner", 123, "failed")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="network/portscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish(
                "command.run.arguments",
                {"args": ["host=192.0.2.10", "ports=80,443", 'arguments="-Pn -sT"']},
                "framework",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"job {job_id}")

            text = output.getvalue()
            self.assertIn(f"job: {job_id}", text)
            self.assertNotIn(f"job: #{job_id}", text)
            self.assertIn("command line: network/portscanner host=192.0.2.10 ports=80,443", text)
            self.assertNotIn(" command=", text)
            self.assertNotIn("command:", text)
            self.assertNotIn("args:", text)
            self.assertIn("'arguments=\"-Pn -sT\"'", text)

    def test_pipeline_show_includes_attached_jobs_and_steps(self):
        """Protect pipeline show includes attached jobs and steps behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner host=192.0.2.10 ports=80,443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.10"},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
                "network/portscanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline 1")

            text = output.getvalue()
            self.assertIn("pipeline: 1", text)
            self.assertIn("Jobs", text)
            self.assertIn("Steps", text)
            self.assertIn("Inspect: job 1; step 1; event step=1; event follow step=1; artifact list step=1", text)
            self.assertIn("INSERTED", text)
            self.assertIn("port.open=1", text)
            self.assertIn("network/portscanner host=192.0.", text)
            self.assertRegex(text, r"\n1\s+completed/finished\s+network/portscanner\s+")

    def test_runtime_detail_views_show_artifact_summaries(self):
        """Protect runtime detail views show artifact summaries behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner host=192.0.2.10 ports=80,443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.10"},
            )
            runner.db.publish(
                "artifact.attached",
                {
                    "artifact_id": "artifact-proof",
                    "artifact_row_id": 7,
                    "name": "scan-output.txt",
                    "content_type": "text/plain",
                    "size": 42,
                    "job_id": job_id,
                },
                "framework",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job 1")
                dispatch_repl_line(runner, "pipeline 1")
                dispatch_repl_line(runner, "step 1")

            text = output.getvalue()
            self.assertEqual(text.count("Artifacts"), 3)
            self.assertIn("#7 scan-output.txt text/plain size=42 artifact-proof", text)
            self.assertIn("inspect artifacts with: artifact list job=1", text)
            self.assertIn("inspect artifacts with: artifact list pipeline=1", text)
            self.assertIn("inspect artifacts with: artifact list step=1", text)

    def test_runtime_views_default_to_chronological_order(self):
        """Protect runtime views default to chronological order behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_job = runner.db.record_job("first", 123, "finished")
            second_job = runner.db.record_job("second", 123, "finished")
            for job_id, pipeline_id, run_id in (
                (first_job, "pipeline-a", "run-a"),
                (second_job, "pipeline-b", "run-b"),
            ):
                runner.db.record_command_run_vars(
                    job_id=job_id,
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                    commandlet="hostscanner",
                    values={"test.marker": str(job_id)},
                )
                runner.db.publish("host.found", {"host": f"192.0.2.{job_id}"}, "hostscanner", pipeline_id=pipeline_id, command_run_id=run_id)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
                dispatch_repl_line(runner, "pipeline")
                dispatch_repl_line(runner, "step")

            text = output.getvalue()
            self.assertLess(text.index("first"), text.index("second"))
            self.assertLess(text.index("\n1         completed/finished"), text.index("\n2         completed/finished"))
            self.assertLess(text.index("\n1     completed/finished"), text.index("\n2     completed/finished"))

    def test_job_show_accepts_durable_serial_selector(self):
        """Protect job show accepts durable serial selector behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            serial = runner.db.job_serial(job_id)
            assert serial is not None

            direct_output = io.StringIO()
            selector_output = io.StringIO()
            with contextlib.redirect_stdout(direct_output):
                dispatch_repl_line(runner, f"job {serial}")
            with contextlib.redirect_stdout(selector_output):
                dispatch_repl_line(runner, f"job serial={serial}")

            self.assertIn(f"serial: {serial.split('-', 1)[1][:8]}", direct_output.getvalue())
            self.assertIn("command line: hostscanner 127.0.0.1", direct_output.getvalue())
            self.assertNotIn("args:", direct_output.getvalue())
            self.assertIn("command line: hostscanner 127.0.0.1", selector_output.getvalue())
            self.assertNotIn("args:", selector_output.getvalue())

    def test_job_show_numeric_serial_prefix_falls_back_after_missing_local_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            with runner.db.connect() as conn:
                conn.execute("UPDATE jobs SET serial = ? WHERE id = ?", ("41864964abcdef", job_id))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job 41864964")

            self.assertIn("serial: 41864964", output.getvalue())
            self.assertIn("command line: hostscanner 127.0.0.1", output.getvalue())

    def test_event_job_selector_accepts_durable_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            serial = runner.db.job_serial(job_id)
            assert serial is not None
            runner.db.publish("job.requested", {"job_id": job_id, "job_serial": serial}, "runner")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event job={serial}")

            self.assertIn(f"#{job_id}", output.getvalue())
            self.assertIn(f"serial={serial}", output.getvalue())

    def test_dispatch_steps_lists_historical_steps_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner done", 123, "finished")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
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
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+hostscanner\s+1\s+0\s+")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step --all")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+hostscanner\s+1\s+0\s+")

    def test_step_listing_hides_view_command_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            view_job = runner.db.record_job("step --all", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=view_job,
                pipeline_id="pipeline-view",
                command_run_id="run-view",
                commandlet="runtime/step",
                values={},
            )
            runner.db.publish(
                "command.run.arguments",
                {
                    "commandlet": "step",
                    "args": ["--all"],
                    "database_actions": ["view"],
                    "job_id": view_job,
                    "pipeline_id": "pipeline-view",
                },
                "framework",
                pipeline_id="pipeline-view",
                command_run_id="run-view",
            )
            work_job = runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=work_job,
                pipeline_id="pipeline-work",
                command_run_id="run-work",
                commandlet="hostscanner",
                values={},
            )
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipeline-work", command_run_id="run-work")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step")
            text = output.getvalue()
            self.assertIn("hostscanner", text)
            self.assertNotIn("runtime/step", text)

    def test_pipeline_listing_hides_view_only_pipelines(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            view_job = runner.db.record_job("step --all", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=view_job,
                pipeline_id="pipeline-view",
                command_run_id="run-view",
                commandlet="runtime/step",
                values={},
            )
            runner.db.publish(
                "command.run.arguments",
                {
                    "commandlet": "step",
                    "args": ["--all"],
                    "database_actions": ["view"],
                    "job_id": view_job,
                    "pipeline_id": "pipeline-view",
                },
                "framework",
                pipeline_id="pipeline-view",
                command_run_id="run-view",
            )
            runner.db.publish(
                "runtime.name.assigned",
                {"target_type": "pipeline", "target_id": "pipeline-view", "name": "view-only"},
                "framework",
                pipeline_id="pipeline-view",
            )
            work_job = runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=work_job,
                pipeline_id="pipeline-work",
                command_run_id="run-work",
                commandlet="hostscanner",
                values={},
            )
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipeline-work", command_run_id="run-work")
            runner.db.publish(
                "runtime.name.assigned",
                {"target_type": "pipeline", "target_id": "pipeline-work", "name": "productive"},
                "framework",
                pipeline_id="pipeline-work",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline")
            text = output.getvalue()
            self.assertIn("productive", text)
            self.assertNotIn("view-only", text)


if __name__ == "__main__":
    unittest.main()
