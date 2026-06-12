# ruff: noqa: F403,F405
"""Report command tests split by responsibility.

Coverage focus: report scope regression behavior.
"""

from tests.report.support import *  # noqa: F403,F405


class ReportScopeTests(unittest.TestCase):
    """Report scope and CVE selector behavior tests.

    These tests construct synthetic event timelines directly in the EventStore
    so report selection can be verified without invoking real scanner plugins.
    """

    def test_report_pipeline_renders_scoped_findings(self):
        """Protect report pipeline renders scoped findings behavior from regressions."""
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

            # The selected pipeline should drive both visible output and the
            # durable report.rendered audit payload.
            text = output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a (1 finding group, 1 event)", text)
            self.assertIn("Missing HSTS", text)
            self.assertNotIn("Other pipeline finding", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["events"], [finding.id])
            self.assertEqual(rendered.payload["groups"], ["finding-1"])
            self.assertEqual(rendered.payload["rows"], 1)

    def test_report_filters_by_cve_exact_wildcard_and_comma_list(self):
        """Protect report filters by CVE exact wildcard and comma list behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            # Publish three independent finding groups so each CVE selector
            # shape can prove its exact inclusion/exclusion behavior.
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-41773",
                    "title": "Apache path traversal",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-41773"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-42013",
                    "title": "Apache path traversal variant",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-42013"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "openssl-heartbleed",
                    "title": "OpenSSL Heartbleed",
                    "target": {"host": "openssl.test"},
                    "identifiers": {"cve": ["CVE-2014-0160"]},
                    "severity": "critical",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-c",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all cve=CVE-2021-41773")
                runner.execute("report pipeline=pipeline-a status=all cve=CVE-2021-*")
                runner.execute("report pipeline=pipeline-a status=all cve=CVE-2021-42013,CVE-2014-0160")
                process_framework_requests(runner, ShellState())

            rendered = runner.db.events_for_topic("report.rendered")
            # exact, wildcard, and comma-list selectors are executed in order
            # above; the audit events preserve the selected group IDs.
            self.assertEqual(rendered[0].payload["groups"], ["apache-41773"])
            self.assertEqual(rendered[1].payload["groups"], ["apache-41773", "apache-42013"])
            self.assertEqual(rendered[2].payload["groups"], ["apache-42013", "openssl-heartbleed"])

    def test_report_expands_related_cves_from_scoped_event_metadata(self):
        """Protect report expands related cves from scoped event metadata behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            # The `+` suffix expands from related_cves attached to the scoped
            # advisory event, not from an external CVE database.
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-advisory",
                    "title": "Apache path traversal advisory",
                    "target": {"host": "apache.test"},
                    "identifiers": {
                        "cve": ["CVE-2021-41773"],
                        "related_cves": ["CVE-2021-42013"],
                    },
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-variant",
                    "title": "Apache path traversal variant",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-42013"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "openssl-heartbleed",
                    "title": "OpenSSL Heartbleed",
                    "target": {"host": "openssl.test"},
                    "identifiers": {"cve": ["CVE-2014-0160"]},
                    "severity": "critical",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-c",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("report pipeline=pipeline-a status=all cve=CVE-2021-41773+")
                process_framework_requests(runner, ShellState())

            rendered = runner.db.events_for_topic("report.rendered")
            self.assertEqual(rendered[0].payload["groups"], ["apache-advisory", "apache-variant"])

    def test_report_related_cve_selector_requires_scoped_metadata(self):
        """Protect report related CVE selector requires scoped metadata behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-41773",
                    "title": "Apache path traversal",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-41773"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            with (
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(ValueError, "has no related CVEs"),
            ):
                runner.execute("report pipeline=pipeline-a status=all cve=CVE-2021-41773+")

    def test_finding_review_filters_by_cve_wildcard(self):
        """Protect finding review filters by CVE wildcard behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-41773",
                    "title": "Apache path traversal",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-41773"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "openssl-heartbleed",
                    "title": "OpenSSL Heartbleed",
                    "target": {"host": "openssl.test"},
                    "identifiers": {"cve": ["CVE-2014-0160"]},
                    "severity": "critical",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("finding confirm all pipeline=pipeline-a status=all cve=CVE-2021-*")

            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(len(reviews), 1)
            self.assertEqual(reviews[0].payload["finding_id"], "apache-41773")

    def test_finding_review_expands_related_cves_from_scoped_event_metadata(self):
        """Protect finding review expands related cves from scoped event metadata behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-advisory",
                    "title": "Apache path traversal advisory",
                    "target": {"host": "apache.test"},
                    "identifiers": {
                        "cve": ["CVE-2021-41773"],
                        "related_cves": ["CVE-2021-42013"],
                    },
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "apache-variant",
                    "title": "Apache path traversal variant",
                    "target": {"host": "apache.test"},
                    "identifiers": {"cve": ["CVE-2021-42013"]},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-b",
            )
            runner.db.publish(
                "finding.new",
                {
                    "finding_id": "openssl-heartbleed",
                    "title": "OpenSSL Heartbleed",
                    "target": {"host": "openssl.test"},
                    "identifiers": {"cve": ["CVE-2014-0160"]},
                    "severity": "critical",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-c",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("finding confirm all pipeline=pipeline-a status=all cve=CVE-2021-41773+")

            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual([review.payload["finding_id"] for review in reviews], ["apache-advisory", "apache-variant"])

    def test_report_last_explicitly_uses_latest_scan_scope(self):
        """Protect report last explicitly uses latest scan scope behavior from regressions."""
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
            # Build an old/new inventory timeline with both host facts and
            # finding facts so `report --new` has to synthesize a delta across
            # multiple topic families.
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
