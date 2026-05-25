"""Tests for operator-facing report behavior.

Provides pytest coverage for the report commandlet and its scoped finding
rendering behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bywaf.app import make_runner, process_framework_requests
from bywaf.repl import ShellState


class ReportTests(unittest.TestCase):
    def test_report_pipeline_renders_scoped_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            finding = runner.db.publish(
                "finding.new",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "target": {"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
                    "severity": "medium",
                },
                "finding_dedupe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "finding-2",
                    "title": "Other pipeline finding",
                    "target": {"host": "other.test"},
                    "severity": "low",
                },
                "finding_dedupe",
                pipeline_id="pipeline-b",
                command_run_id="run-b",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 1 event)", text)
            self.assertIn("Missing HSTS", text)
            self.assertNotIn("Other pipeline finding", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [finding.id])
            self.assertEqual(rendered.payload["groups"], ["finding-1"])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_pipeline_renders_candidate_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            candidate = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Telnet service exposed",
                    "target": {"host": "192.0.2.10", "port": "23"},
                    "severity": "medium",
                    "class": "service.telnet.exposed",
                },
                "portscanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Telnet service exposed", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [candidate.id])
            self.assertEqual(rendered.payload["groups"], ["candidate-1"])

    def test_report_groups_duplicate_finding_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Telnet service exposed",
                    "target": {"host": "192.0.2.10", "port": "23"},
                    "severity": "medium",
                },
                "portscanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            second = runner.db.publish(
                "finding.new",
                {
                    "finding_id": "finding-1",
                    "title": "Telnet service exposed",
                    "target": {"host": "192.0.2.10", "port": "23"},
                    "severity": "medium",
                },
                "finding_dedupe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 2 events)", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [first.id, second.id])
            self.assertEqual(rendered.payload["groups"], ["finding-1"])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_groups_by_explicit_group_key_before_finding_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-1",
                    "group_key": "service|CVE-2026-1234|192.0.2.10|443|tcp",
                    "title": "Example service CVE",
                    "target": {"ip": "192.0.2.10", "port": "443", "protocol": "tcp"},
                    "affected": [{"url": "https://example.test/page1"}],
                    "severity": "high",
                },
                "web_cve_check",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            second = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-2",
                    "group_key": "service|CVE-2026-1234|192.0.2.10|443|tcp",
                    "title": "Example service CVE",
                    "target": {"ip": "192.0.2.10", "port": "443", "protocol": "tcp"},
                    "affected": [{"url": "https://example.test/admin"}],
                    "severity": "high",
                },
                "web_cve_check",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 2 events)", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [first.id, second.id])
            self.assertEqual(rendered.payload["groups"], ["service|CVE-2026-1234|192.0.2.10|443|tcp"])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_derives_group_key_from_class_scope_and_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-1",
                    "class": "web.xss.reflected",
                    "title": "Example web CVE",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"scheme": "https", "host": "example.test", "path": "/page1"},
                    "identifiers": {"cve": ["CVE-2026-1234"]},
                    "affected": [{"url": "https://example.test/page1"}],
                    "severity": "high",
                },
                "web_cve_check",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            second = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-2",
                    "class": "web.xss.reflected",
                    "title": "Example web CVE",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"scheme": "https", "host": "example.test", "path": "/admin"},
                    "identifiers": {"cve": ["CVE-2026-1234"]},
                    "affected": [{"url": "https://example.test/admin"}],
                    "severity": "high",
                },
                "web_cve_check",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 2 events)", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [first.id, second.id])
            self.assertEqual(
                rendered.payload["groups"],
                ["web.xss.reflected|web_origin:https://example.test|cve:CVE-2026-1234"],
            )
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_new_uses_latest_completed_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="pipeline-old",
                command_run_id="run-old",
                commandlet="scanner",
                values={},
            )
            runner.db.publish("command.run.completed", {}, "scanner", pipeline_id="pipeline-old", command_run_id="run-old")
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="pipeline-new",
                command_run_id="run-new",
                commandlet="scanner",
                values={},
            )
            runner.db.publish("command.run.completed", {}, "scanner", pipeline_id="pipeline-new", command_run_id="run-new")
            runner.db.publish(
                "finding.new",
                {"finding_id": "old", "title": "Old finding", "target": {"host": "old.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-old",
                command_run_id="run-old",
            )
            runner.db.publish(
                "finding.new",
                {"finding_id": "new", "title": "New finding", "target": {"host": "new.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-new",
                command_run_id="run-new",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report new")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("latest completed pipeline", text)
            self.assertIn("New finding", text)
            self.assertNotIn("Old finding", text)

    def test_report_new_hides_reviewed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="scanner",
                values={},
            )
            runner.db.publish("command.run.completed", {}, "scanner", pipeline_id="pipeline-a", command_run_id="run-a")
            runner.db.publish(
                "finding.new",
                {"finding_id": "finding-1", "title": "Reviewed finding", "target": {"host": "example.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish("finding.reviewed", {"finding_id": "finding-1"}, "report")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report new")
                process_framework_requests(runner, ShellState())

            self.assertIn("no unreviewed findings", output.getvalue())

    def test_report_job_accepts_multiple_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first_job = runner.db.record_job("scanner a", None, "completed")
            second_job = runner.db.record_job("scanner b", None, "completed")
            runner.db.record_command_run_vars(
                job_id=first_job,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="scanner",
                values={"target": "a.test"},
            )
            runner.db.record_command_run_vars(
                job_id=second_job,
                pipeline_id="pipeline-b",
                command_run_id="run-b",
                commandlet="scanner",
                values={"target": "b.test"},
            )
            runner.db.publish(
                "finding.new",
                {"finding_id": "finding-1", "title": "First finding", "target": {"host": "a.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {"finding_id": "finding-2", "title": "Second finding", "target": {"host": "b.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-b",
                command_run_id="run-b",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"report job={first_job},{second_job}")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("First finding", text)
            self.assertIn("Second finding", text)


if __name__ == "__main__":
    unittest.main()
