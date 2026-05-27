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

    def test_report_compacts_multiline_evidence_in_table_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Exposed Git repository configuration",
                    "target": {"url": "http://127.0.0.1:8088/.git/config"},
                    "severity": "high",
                    "evidence": "[core]\n\trepositoryformatversion = 0\n",
                },
                "git_expose_check",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("[core] repositoryformatversion = 0", text)
            self.assertNotIn("[core]\n\t", text)

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

    def test_report_review_marker_matches_raw_finding_id_inside_group_key_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
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
            runner.db.publish(
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
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-page-1", "decision": "accepted"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Findings: 1 total, 1 accepted, 0 deferred, 0 rejected, 0 unreviewed", text)
            self.assertIn("no unreviewed findings", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["groups"], [])
            self.assertEqual(rendered.payload["rows"], 0)

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

    def test_report_splits_same_cve_when_target_scope_is_route_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-1",
                    "class": "web.xss.reflected",
                    "title": "Example web CVE",
                    "target_scope": {"kind": "web_route", "value": "https://example.test/page1"},
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
                    "target_scope": {"kind": "web_route", "value": "https://example.test/admin"},
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
            self.assertIn("Report scope: pipeline=pipeline-a (2 finding groups, 2 events)", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [first.id, second.id])
            self.assertEqual(
                rendered.payload["groups"],
                [
                    "web.xss.reflected|web_route:https://example.test/page1|cve:CVE-2026-1234",
                    "web.xss.reflected|web_route:https://example.test/admin|cve:CVE-2026-1234",
                ],
            )
            self.assertEqual(rendered.payload["rows"], 2)

    def test_report_defaults_to_latest_completed_pipeline(self):
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
                runner.execute("report")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("latest completed pipeline", text)
            self.assertIn("New finding", text)
            self.assertNotIn("Old finding", text)

    def test_report_hides_reviewed_findings(self):
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
                runner.execute("report")
                process_framework_requests(runner, ShellState())

            self.assertIn("no unreviewed findings", output.getvalue())

    def test_report_summarizes_review_state_and_shows_unreviewed_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index, title in enumerate(("Accepted finding", "Deferred finding", "Open finding"), start=1):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": title,
                        "target": {"host": f"host-{index}.test"},
                        "severity": "medium",
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-2", "decision": "deferred"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Findings: 3 total, 1 accepted, 1 deferred, 0 rejected, 1 unreviewed", text)
            self.assertIn("Unreviewed findings:", text)
            self.assertIn("Open finding", text)
            self.assertNotIn("Accepted finding", text)
            self.assertNotIn("Deferred finding", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(
                rendered.payload["counts"],
                {"total": 3, "accepted": 1, "deferred": 1, "rejected": 0, "unreviewed": 1},
            )
            self.assertEqual(rendered.payload["groups"], ["finding-3"])

    def test_report_status_all_shows_reviewed_and_unreviewed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Accepted finding", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-2", "title": "Open finding", "target": {"host": "b.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("All findings:", text)
            self.assertIn("Accepted finding", text)
            self.assertIn("Open finding", text)

    def test_report_accepts_selection_ranges_and_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index in range(1, 6):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": f"Finding {index}",
                        "target": {"host": f"host-{index}.test"},
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report accept 1-2,4 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("accepted 3 findings", output.getvalue())
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(
                [(event.payload["finding_id"], event.payload["decision"]) for event in reviews],
                [("finding-1", "accepted"), ("finding-2", "accepted"), ("finding-4", "accepted")],
            )

    def test_report_accept_all_marks_visible_unreviewed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index in range(1, 4):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": f"Finding {index}",
                        "target": {"host": f"host-{index}.test"},
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report accept all pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("accepted 3 findings", output.getvalue())
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(len(reviews), 3)
            self.assertTrue(all(event.payload["decision"] == "accepted" for event in reviews))

    def test_report_defer_records_note_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Needs review", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report defer 1 pipeline=pipeline-a note=needs manual validation")
                process_framework_requests(runner, ShellState())

            self.assertIn("deferred 1 finding", output.getvalue())
            review = runner.db.events_for_topic("finding.reviewed")[0]
            self.assertEqual(review.payload["finding_id"], "finding-1")
            self.assertEqual(review.payload["decision"], "deferred")
            self.assertEqual(review.payload["note"], "needs manual validation")

    def test_report_latest_review_decision_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Flipped finding", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "rejected"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=rejected")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Findings: 1 total, 0 accepted, 0 deferred, 1 rejected, 0 unreviewed", text)
            self.assertIn("Rejected findings:", text)
            self.assertIn("Flipped finding", text)

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
