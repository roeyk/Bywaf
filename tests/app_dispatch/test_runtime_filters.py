"""Tests for app runtime filters behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch runtime filters regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    make_runner,
)
from bywaf.db import EventStore



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app runtime filters behavior."""
    def test_make_runner_marks_dead_runtime_jobs_stale_on_startup(self):
        """Protect make runner marks dead runtime jobs stale on startup behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            db = EventStore(db_path)
            job_id = db.record_job("hostscanner 127.0.0.1", 99999999, "running")
            db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner = make_runner(db_path)
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "stale")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline")
            self.assertIn("failed/stale", output.getvalue())

    def test_job_lists_by_default(self):
        """Protect job lists by default behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
            text = output.getvalue()
            self.assertIn("ART", text)
            self.assertIn("COMMAND", text)
            self.assertNotIn("COMMANDLET", text)
            self.assertRegex(text, r"\n1\s+active/running\s+")
            self.assertIn("hostscanner 127.0.0.1", text)

    def test_job_listing_hides_view_command_jobs(self):
        """Protect job listing hides view command jobs behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
            report_job = runner.db.record_job("report status=all", 123, "finished")
            runner.db.record_job("report accept all note=confirmed", 123, "finished")
            runner.db.record_job("artifact list topic=port.open", 123, "finished")
            runner.db.record_job("artifact attach file=evidence.txt", 123, "finished")
            runner.db.record_job("runtime/step --all", 123, "finished")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")
                dispatch_repl_line(runner, f"job {report_job}")

            text = output.getvalue()
            self.assertIn("hostscanner 127.0.0.1", text)
            self.assertNotIn("report status=all", text.split("Job summary", 1)[0])
            self.assertNotIn("runtime/step --all", text.split("Job summary", 1)[0])
            self.assertNotIn("artifact list topic=port.open", text.split("Job summary", 1)[0])
            self.assertIn("report accept all note=confirmed", text)
            self.assertIn("artifact attach file=evidence", text)
            self.assertIn("command line: report status=all", text)

    def test_job_listing_uses_recorded_database_actions_for_view_filtering(self):
        """Protect job listing uses recorded database actions for view filtering behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            view_job = runner.db.record_job("custom_view", 123, "finished")
            runner.db.publish(
                "command.run.arguments",
                {"args": [], "database_actions": ["view"], "job_id": view_job},
                "framework",
                pipeline_id="pipeline-view",
                command_run_id="run-view",
            )
            work_job = runner.db.record_job("custom_write", 123, "finished")
            runner.db.publish(
                "command.run.arguments",
                {"args": [], "database_actions": ["write"], "job_id": work_job},
                "framework",
                pipeline_id="pipeline-work",
                command_run_id="run-work",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")

            text = output.getvalue()
            self.assertNotIn("custom_view", text)
            self.assertIn("custom_write", text)

    def test_job_listing_filters_by_status_and_commandlet_rows(self):
        """Protect job listing filters by status and commandlet rows behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("missing", 123, "failed")
            runner.db.record_job("hostscanner 127.0.0.1", 123, "failed")
            runner.db.record_job("missing", 123, "finished")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all status=failed commandlet=missing")

            text = output.getvalue()
            self.assertIn("failed", text)
            self.assertIn("missing", text)
            self.assertNotIn("hostscanner 127.0.0.1", text)
            self.assertNotIn("completed/finished", text)

    def test_job_listing_filters_by_command_substring(self):
        """Protect job listing filters by command substring behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
            runner.db.record_job("portscanner host=127.0.0.1", 123, "finished")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all command=portscanner")

            text = output.getvalue()
            self.assertIn("portscanner host=127.0.0.1", text)
            self.assertNotIn("hostscanner 127.0.0.1", text)

    def test_jobs_all_marks_active_state(self):
        """Protect jobs all marks active state behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("active", 123, "running")
            runner.db.record_job("old", 456, "finished")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")
            text = output.getvalue()
            self.assertRegex(text, r"\n1\s+active/running\s+")
            self.assertRegex(text, r"\n2\s+completed/finished\s+")

    def test_job_list_styles_active_row_and_status_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.table.active_row", "green")
            runner.registry.varstore.set("display/style.table.active_column", "bold white")
            runner.db.record_job("active", 123, "running")
            runner.db.record_job("old", 456, "finished")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
            text = output.getvalue()
            self.assertIn("\x1b[32m1", text)
            self.assertIn("\x1b[1;37mactive/running", text)
            self.assertIn("completed/finished", text)
            completed_row = next(line for line in text.splitlines() if "completed/finished" in line)
            self.assertNotIn("\x1b[", completed_row)

    def test_job_listing_fits_terminal_width(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job(
                "network/portscanner host=192.0.2.10 ports=1-65535 arguments='-Pn -sT -4'",
                123,
                "running",
            )
            output = io.StringIO()
            with (
                patch("bywaf.runtime_table_widths.shutil.get_terminal_size", return_value=os.terminal_size((72, 24))),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "job --all")
            lines = [line for line in output.getvalue().splitlines() if line]
            self.assertTrue(lines)
            self.assertTrue(all(len(line) <= 72 for line in lines), output.getvalue())

    def test_runtime_views_accept_sort_selector_and_reject_sort_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job sort=started")
                dispatch_repl_line(runner, "job sort=-started")
                dispatch_repl_line(runner, "pipeline sort=events")
                dispatch_repl_line(runner, "step sort=started")
                dispatch_repl_line(runner, "pipeline --sort=events")

            text = output.getvalue()
            self.assertIn("sorted by started ascending (use sort=-started to sort descending)", text)
            self.assertIn("sorted by started descending (use sort=started to sort ascending)", text)
            self.assertIn("sorted by events ascending (use sort=-events to sort descending)", text)
            self.assertIn("sorted by started ascending (use sort=-started to sort descending)", text)
            self.assertIn("error: pipeline uses selector syntax; use sort=<key>, not --sort=events", text)

    def test_runtime_view_filters_share_event_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_job = runner.db.record_job("portscanner host=192.0.2.10", 123, "finished")
            second_job = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            for job_id, pipeline_id, run_id, host in (
                (first_job, "pipe-1", "run-1", "192.0.2.10"),
                (second_job, "pipe-2", "run-2", "192.0.2.20"),
            ):
                runner.db.record_command_run_vars(
                    job_id=job_id,
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                    commandlet="portscanner",
                    values={},
                )
                runner.db.publish(
                    "port.open",
                    {"host": host, "port": 80, "protocol": "tcp"},
                    "portscanner",
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")

            text = output.getvalue()
            self.assertIn("portscanner host=192.0.2.20", text)
            self.assertIn("PIPELINE", text)
            self.assertIn("STEP", text)
            self.assertIn("2", text)
            self.assertNotIn("portscanner host=192.0.2.10", text)

    def test_runtime_views_filter_since_local_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_job = runner.db.record_job("portscanner host=192.0.2.10", 123, "finished")
            second_job = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            for job_id, pipeline_id, run_id, host in (
                (first_job, "pipe-since-1", "run-since-1", "192.0.2.10"),
                (second_job, "pipe-since-2", "run-since-2", "192.0.2.20"),
            ):
                runner.db.record_command_run_vars(
                    job_id=job_id,
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                    commandlet="portscanner",
                    values={},
                )
                runner.db.publish(
                    "port.open",
                    {"host": host, "port": 80, "protocol": "tcp"},
                    "portscanner",
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"job since={first_job}")
                dispatch_repl_line(runner, "pipeline since=1")
                dispatch_repl_line(runner, "step since=1")

            text = output.getvalue()
            self.assertIn("after job 1", text)
            self.assertIn("after pipeline 1", text)
            self.assertIn("after step 1", text)
            self.assertIn("portscanner host=192.0.2.20", text)
            self.assertNotIn("portscanner host=192.0.2.10", text)

    def test_runtime_views_new_uses_operator_cursors(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-new-1",
                command_run_id="run-new-1",
                commandlet="portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 80, "protocol": "tcp"},
                "portscanner",
                pipeline_id="pipe-new-1",
                command_run_id="run-new-1",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --new")
                dispatch_repl_line(runner, "pipeline --new")
                dispatch_repl_line(runner, "step --new")
                dispatch_repl_line(runner, "job --new")
                dispatch_repl_line(runner, "pipeline --new")
                dispatch_repl_line(runner, "step --new")

            text = output.getvalue()
            self.assertIn("portscanner host=192.0.2.20", text)
            self.assertIn("PIPELINE", text)
            self.assertIn("STEP", text)
            self.assertIn("no new jobs", text)
            self.assertIn("no new pipelines", text)
            self.assertIn("no new steps", text)
            self.assertTrue(Path(tmp, "view-cursors.json").exists())

    def test_db_new_resets_repl_framework_request_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "old.sqlite3"))
            for index in range(5):
                runner.db.publish("noise", {"index": index}, "test")
            state = ShellState(framework_request_after_id=runner.db.latest_event_id())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"db new file={Path(tmp, 'new.sqlite3')}", state)
                runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
                dispatch_repl_line(runner, "job --all", state)

            text = output.getvalue()
            self.assertIn("created db=", text)
            self.assertIn("hostscanner", text)

    def test_job_listing_keeps_state_short_when_long_active_format_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.listing.active-format", "long")
            runner.db.record_job("active", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")
            self.assertNotIn("active since ", output.getvalue())
            self.assertRegex(output.getvalue(), r"\n1\s+active/running\s+")

    def test_pipeline_lists_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline")
            text = output.getvalue()
            self.assertIn("ART", text)
            self.assertRegex(text, rf"\n1\s+active/running\s+{job_id}\s+1\s+0\s+0\s+")

    def test_pipeline_list_lists_historical_pipelines_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner done", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="finished-pipe",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+1\s+0\s+0\s+")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline --all")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+1\s+0\s+0\s+")


if __name__ == "__main__":
    unittest.main()
