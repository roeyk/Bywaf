# ruff: noqa: F403,F405
"""Report command tests split by responsibility.

Coverage focus: report grouping regression behavior.
"""

from tests.report.support import *  # noqa: F403,F405
class ReportGroupingTests(unittest.TestCase):
    """Groups regression coverage for report command tests split by responsibility."""
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
                runner.execute("report detail 1 pipeline=pipeline-a")
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

    def test_report_details_show_grouped_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-page-1",
                    "group_key": "web|CVE-2026-1234|192.0.2.10",
                    "title": "Example service CVE",
                    "target": {"ip": "192.0.2.10", "port": "443", "protocol": "tcp"},
                    "affected": [{"url": "https://example.test/page1"}],
                    "evidence": "page1 proof\nwith newline",
                    "sources": [{"tool": "web_cve_check", "topic": "http.response"}],
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
                    "group_key": "web|CVE-2026-1234|192.0.2.10",
                    "title": "Example service CVE",
                    "target": {"ip": "192.0.2.10", "port": "443", "protocol": "tcp"},
                    "affected": [{"url": "https://example.test/admin"}],
                    "evidence": "admin proof",
                    "severity": "high",
                },
                "web_cve_check",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )
            runner.db.publish(
                "artifact.attached",
                {
                    "artifact_id": "artifact-proof",
                    "artifact_row_id": 3,
                    "name": "proof.txt",
                    "content_type": "text/plain",
                    "size": 12,
                },
                "framework",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report detail 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Details", text)
            self.assertIn("1. Example service CVE", text)
            self.assertIn("Affected: https://example.test/page1; https://example.test/admin", text)
            self.assertIn("Evidence: page1 proof with newline; admin proof", text)
            self.assertIn("Sources: web_cve_check:http.response; web_cve_check:finding.candidate", text)
            self.assertIn("Artifacts: #3 proof.txt text/plain size=12 artifact-proof", text)
            self.assertIn("Inspect artifacts with: artifact list step=run-a", text)
            self.assertIn(f"Provenance: events={first.id},{second.id}; pipeline=pipeline-a; step=run-a,run-b", text)
            self.assertIn("Latest update:", text)

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
            self.assertIn("Findings: 1 total", text)
            self.assertIn("Review: 1 accepted, 0 confirmed, 0 deferred, 0 rejected, 0 unreviewed", text)
            self.assertIn("no open findings", text)
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

    def test_report_inbox_summarizes_grouped_affected_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            first = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "git-config-one",
                    "class": "web.exposure.git_config",
                    "title": "Exposed Git repository configuration",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"}],
                    "severity": "high",
                },
                "http_paths",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            second = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "git-config-two",
                    "class": "web.exposure.git_config",
                    "title": "Exposed Git repository configuration",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"}],
                    "severity": "high",
                },
                "repo_exposure",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )

            output = io.StringIO()
            with (
                patch("bywaf.runtime_table_widths.shutil.get_terminal_size", return_value=os.terminal_size((180, 24))),
                contextlib.redirect_stdout(output),
            ):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 2 events)", text)
            self.assertIn("2 affected: https://example.test/.git/config; https://example.test/app/.git/config", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [first.id, second.id])
            self.assertEqual(rendered.payload["groups"], ["web.exposure.git_config|web_origin:https://example.test|cwe:CWE-538"])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_detail_uses_deduped_canonical_affected_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "git-config-one",
                    "class": "web.exposure.git_config",
                    "title": "Exposed Git repository configuration",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"}],
                    "evidence": "root config returned",
                    "severity": "high",
                },
                "http_paths",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "git-config-two",
                    "class": "web.exposure.git_config",
                    "title": "Exposed Git repository configuration",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"}],
                    "evidence": "app config returned",
                    "severity": "high",
                },
                "repo_exposure",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("finding_dedupe -s | report detail 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 1 event)", text)
            self.assertIn("Affected: https://example.test/.git/config; https://example.test/app/.git/config", text)
            self.assertIn("Sources: http_paths:finding.candidate; repo_exposure:finding.candidate", text)
            self.assertIn("Provenance: events=", text)

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
