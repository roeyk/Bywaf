"""Tests for operator-facing report behavior.

Provides pytest coverage for the report commandlet and its scoped finding
rendering behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import dispatch_repl_line, make_runner, process_framework_requests
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

    def test_report_sort_host_groups_findings_under_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "target": {"host": "web-1.test"},
                    "severity": "medium",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-2",
                    "title": "Telnet exposed",
                    "target": {"host": "web-1.test"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a sort=host")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report: grouped by host", text)
            self.assertIn("Use sort=finding to group affected hosts under each finding.", text)
            self.assertIn("Hosts", text)
            self.assertIn("web-1.test", text)
            self.assertIn("Missing HSTS [medium, unreviewed]; Telnet exposed [high, unreviewed]", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["sort"], "host")
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_finding_rows_always_show_review_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "target": {"host": "web-1.test"},
                    "severity": "medium",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Review", text)
            self.assertIn("unreviewed", text)

    def test_report_last_explicitly_uses_latest_scan_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "old", "title": "Old finding", "target": {"host": "old.test"}},
                "scanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report --last")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: latest scan", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("Old finding", text)

    def test_report_new_renders_composite_inventory_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "status": "up"},
                "hostscanner",
                pipeline_id="old-host-pipeline",
                command_run_id="old-host-step",
            )
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "status": "up"},
                "hostscanner",
                pipeline_id="new-host-pipeline",
                command_run_id="new-host-step",
            )
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.20", "status": "up"},
                "hostscanner",
                pipeline_id="new-host-pipeline",
                command_run_id="new-host-step",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "old", "title": "Old finding", "target": {"host": "192.0.2.10"}},
                "scanner",
                pipeline_id="old-finding-pipeline",
                command_run_id="old-finding-step",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "new", "title": "New finding", "target": {"host": "192.0.2.20"}},
                "scanner",
                pipeline_id="new-finding-pipeline",
                command_run_id="new-finding-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report --new status=all")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report new: since prior inventory", text)
            self.assertIn("192.0.2.20", text)
            self.assertIn("New finding", text)
            self.assertNotIn("Old finding", text)

    def test_report_repl_does_not_echo_rendered_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "target": {"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
                    "severity": "medium",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "report pipeline=pipeline-a", ShellState())

            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a", text)
            self.assertIn("Missing HSTS", text)
            self.assertNotIn("report.rendered", text)
            self.assertEqual(len(runner.db.events_for_topic("report.rendered")), 1)

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

    def test_report_shows_network_overview_for_selected_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "name": "web.test", "status": "up"},
                "hostscanner",
                pipeline_id="pipeline-a",
                command_run_id="host-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"},
                "portscanner",
                pipeline_id="pipeline-a",
                command_run_id="port-step",
            )
            runner.db.publish(
                "http.endpoint",
                {"url": "https://web.test/", "host": "192.0.2.10", "port": 443, "scheme": "https"},
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="http-step",
            )
            runner.db.publish(
                "web.screenshotted_host",
                {"host": "192.0.2.10", "urls": ["https://web.test/"], "screenshots": [{"artifact_id": "artifact-1"}]},
                "screenshotter",
                pipeline_id="pipeline-a",
                command_run_id="shot-step",
            )
            runner.db.publish(
                "network.route.hop",
                {"target": "192.0.2.10", "hop": 1, "host": "192.0.2.10", "ip": "192.0.2.10", "status": "responded"},
                "traceroute",
                pipeline_id="pipeline-a",
                command_run_id="route-step",
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "class": "web.header.missing_hsts",
                    "target": {"host": "192.0.2.10"},
                    "severity": "medium",
                },
                "http_headers",
                pipeline_id="pipeline-a",
                command_run_id="finding-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Network overview", text)
            self.assertIn("192.0.2.10", text)
            self.assertIn("443/tcp https", text)
            self.assertIn("https://web.test/", text)
            self.assertIn("screenshots:1", text)
            self.assertIn("hop:1", text)
            self.assertIn("Missing HSTS", text)

    def test_report_network_renders_network_only_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            host_event = runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "name": "web.test", "status": "up"},
                "hostscanner",
                pipeline_id="pipeline-a",
                command_run_id="host-step",
            )
            port_event = runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"},
                "portscanner",
                pipeline_id="pipeline-a",
                command_run_id="port-step",
            )
            http_event = runner.db.publish(
                "http.endpoint",
                {"url": "https://web.test/", "host": "192.0.2.10", "port": 443, "scheme": "https"},
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="http-step",
            )
            finding = runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Missing HSTS",
                    "class": "web.header.missing_hsts",
                    "target": {"host": "192.0.2.10"},
                    "severity": "medium",
                },
                "http_headers",
                pipeline_id="pipeline-a",
                command_run_id="finding-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report network pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Report network: pipeline=pipeline-a (1 host, 4 events)", text)
            self.assertIn("Network overview", text)
            self.assertIn("192.0.2.10", text)
            self.assertIn("443/tcp https", text)
            self.assertIn("https://web.test/", text)
            self.assertIn("Missing HSTS", text)
            self.assertNotIn("Finding detail:", text)
            self.assertNotIn("Unreviewed findings:", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["action"], "network")
            self.assertEqual(rendered.payload["events"], [host_event.id, port_event.id, http_event.id, finding.id])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_defaults_to_latest_network_scope_without_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "old-finding",
                    "title": "Old finding",
                    "class": "old.example",
                    "target": {"host": "192.0.2.1"},
                },
                "scanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 22, "protocol": "tcp", "service": "ssh"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Network overview", text)
            self.assertIn("192.0.2.20", text)
            self.assertIn("no unreviewed findings", text)
            self.assertNotIn("Old finding", text)

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
                runner.execute("report detail 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("[core] repositoryformatversion = 0", text)
            self.assertNotIn("[core]\n\t", text)

    def test_report_summary_table_fits_terminal_width(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Very long finding title that should be shortened in the summary table",
                    "target": {"url": "http://127.0.0.1:8088/.git/config"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with (
                patch("bywaf.runtime_display.shutil.get_terminal_size", return_value=os.terminal_size((72, 24))),
                contextlib.redirect_stdout(output),
            ):
                runner.execute("report pipeline=pipeline-a page=false")
                process_framework_requests(runner, ShellState())

            lines = [line for line in output.getvalue().splitlines() if line and "\x1b[" not in line]
            self.assertTrue(all(len(line) <= 72 for line in lines), output.getvalue())
            self.assertIn("…", output.getvalue())

    def test_report_applies_configured_table_and_finding_styles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.registry.varstore.set("display/style.table.header", "bold yellow")
            runner.registry.varstore.set("display/style.table.index", "cyan")
            runner.registry.varstore.set("display/style.finding.severity.high", "bold red")
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Styled finding",
                    "target": {"host": "example.test"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("\x1b[1;33mFinding", text)
            self.assertIn("\x1b[36m1", text)
            self.assertIn("\x1b[1;31mhigh", text)

    def test_report_summarizes_and_styles_severity_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.registry.varstore.set("display/style.finding.severity_class.urgent", "bold red")
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Classed finding",
                    "target": {"host": "example.test"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("severity classes: 1 urgent", text)
            self.assertIn("\x1b[1;31mhigh", text)

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
            self.assertIn("Affected: https://example.test/page1; 192.0.2.10:443/tcp; https://example.test/admin", text)
            self.assertIn("Evidence: page1 proof with newline; admin proof", text)
            self.assertIn("Sources: web_cve_check:http.response; web_cve_check:finding.candidate", text)
            self.assertIn("Artifacts: #3 proof.txt text/plain size=12 artifact-proof", text)
            self.assertIn(f"Provenance: events={first.id},{second.id}; pipeline=pipeline-a; step=run-a,run-b", text)
            self.assertIn("Latest update:", text)

    def test_report_prints_inline_by_default_and_can_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Paged finding",
                    "target": {"host": "example.test"},
                    "severity": "medium",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.events_for_topic("framework.file.page.requested"), [])

            runner = make_runner(Path(tmp, "bywaf-page.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "candidate-1",
                    "title": "Paged finding",
                    "target": {"host": "example.test"},
                    "severity": "medium",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("report pipeline=pipeline-a page=true")
                process_framework_requests(runner, ShellState())
            self.assertEqual(len(runner.db.events_for_topic("framework.file.page.requested")), 1)

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
            self.assertIn("latest scan", text)
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
            capabilities = runner.db.events_for_topic("plugin.capability.used")
            self.assertTrue(any(event.payload.get("capability") == "finding.review" for event in capabilities))

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
                first_serial = runner.db.job_serial(first_job)
                assert first_serial is not None
                runner.execute(f"report job={first_serial},{second_job}")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("First finding", text)
            self.assertIn("Second finding", text)


if __name__ == "__main__":
    unittest.main()
