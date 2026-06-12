# ruff: noqa: F403,F405
"""Report command tests split by responsibility.

Coverage focus: report network regression behavior.
"""

from tests.report.support import *  # noqa: F403,F405
class ReportNetworkTests(unittest.TestCase):
    """Groups regression coverage for report command tests split by responsibility."""
    def test_report_shows_network_overview_for_selected_scope(self):
        """Protect report shows network overview for selected scope behavior from regressions."""
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
        """Protect report network renders network only scope behavior from regressions."""
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
            self.assertIn("no open findings", text)
            self.assertNotIn("Old finding", text)
