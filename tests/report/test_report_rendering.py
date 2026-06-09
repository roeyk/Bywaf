# ruff: noqa: F403,F405
"""Report command tests split by responsibility."""

from tests.report.support import *  # noqa: F403,F405
class ReportRenderingTests(unittest.TestCase):
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

    def test_report_marks_confirmed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.confirmed",
                {
                    "finding_id": "finding-1",
                    "title": "Exposed Git repository configuration",
                    "target": {"host": "web-1.test"},
                    "severity": "high",
                    "status": "confirmed",
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
            self.assertIn("Exposed Git repository configuration (confirmed)", text)
            self.assertIn("Findings: 1 total", text)
            self.assertIn("Resume: 1 open finding needs review (1 confirmed, 0 unreviewed)", text)
            self.assertIn("Resume focus: 1 urgent", text)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report detail 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("Finding status: confirmed", output.getvalue())

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

    def test_report_marks_confidence_basis_for_indicator_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "indicator-1",
                    "title": "Apache httpd 2.4.49 version indicator observed",
                    "target": {"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
                    "severity": "high",
                    "confidence": "medium",
                    "confidence_basis": "version_indicator",
                },
                "technology_indicators",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Basis", text)
            self.assertIn("version indicator", text)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report detail 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("Confidence basis: version indicator", output.getvalue())

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
                patch("bywaf.runtime_table_widths.shutil.get_terminal_size", return_value=os.terminal_size((72, 24))),
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
