"""Tests for app results behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch results regression behavior.
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
    """Groups regression coverage for app results behavior."""
    def test_results_defaults_to_latest_operator_job(self):
        """Protect results defaults to latest operator job behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            new_job = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=new_job,
                pipeline_id="new-pipeline",
                command_run_id="new-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )
            runner.db.publish(
                "report.rendered",
                {"rows": 1},
                "report",
                pipeline_id="report-pipeline",
                command_run_id="report-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn(f"Results: latest job={new_job}", text)
            self.assertIn("Shared schemas: port.open", text)
            self.assertIn("Output of: ports", text)
            self.assertIn(f"Equivalent command: ports job={new_job} sort=host", text)
            self.assertIn(f"Ports: job={new_job}", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)
            self.assertNotIn("report.rendered", text)

    def test_results_hides_framework_alert_noise(self):
        """Protect results hides framework alert noise behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "framework.console.alert.requested",
                {"message": "alert: discovered port 443/tcp on host 192.0.2.20"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "console.alert",
                {"message": "alert: discovered port 443/tcp on host 192.0.2.20"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results pipeline=1")

            text = output.getvalue()
            self.assertIn("Output of: ports", text)
            self.assertIn("Equivalent command: ports pipeline=1 sort=host", text)
            self.assertIn("Ports: pipeline=1", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("framework.console.alert", text)
            self.assertNotIn("console.alert", text)

    def test_results_renders_shared_schema_summaries(self):
        """Protect results renders shared schema summaries behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("http_probe", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="http_probe",
                values={},
            )
            runner.db.publish("host.found", {"host": "192.0.2.20", "status": "up"}, "hostscanner", pipeline_id="scan-pipeline", command_run_id="scan-step")
            runner.db.publish("name.resolved", {"name": "example.test", "host": "192.0.2.20"}, "hostscanner", pipeline_id="scan-pipeline", command_run_id="scan-step")
            runner.db.publish(
                "http.endpoint",
                {"url": "https://example.test/", "host": "example.test", "port": 443, "scheme": "https", "status": 200, "server": "nginx"},
                "http_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: host.found, http.endpoint, name.resolved", text)
            self.assertIn("Hosts discovered", text)
            self.assertIn("Name resolutions", text)
            self.assertIn("HTTP endpoints", text)
            self.assertIn("https://example.test/", text)

    def test_results_renders_web_fingerprint_summary(self):
        """Protect results renders web fingerprint summary behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("webfin https://example.test/", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="web-pipeline",
                command_run_id="webfin-step",
                commandlet="webfin",
                values={},
            )
            runner.db.publish(
                "web.fingerprint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "status": 200,
                    "server": "nginx",
                    "technologies": ["nginx", "jquery"],
                    "observations": [
                        {"severity": "low", "message": "missing header"},
                        {"severity": "info", "message": "server header"},
                    ],
                    "interesting": True,
                },
                "webfin",
                pipeline_id="web-pipeline",
                command_run_id="webfin-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: web.fingerprint", text)
            self.assertIn("Web fingerprints", text)
            self.assertIn("nginx", text)
            self.assertIn("info:1", text)
            self.assertNotIn("Representative events", text)

    def test_results_renders_http_headers_summary(self):
        """Protect results renders HTTP headers summary behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("http_headers example.test", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="headers-pipeline",
                command_run_id="headers-step",
                commandlet="http_headers",
                values={},
            )
            runner.db.publish(
                "http.headers",
                {
                    "host": "example.test",
                    "port": 443,
                    "status": 200,
                    "headers": {"server": "nginx"},
                },
                "http_headers",
                pipeline_id="headers-pipeline",
                command_run_id="headers-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: http.headers", text)
            self.assertIn("HTTP headers", text)
            self.assertIn("example.test", text)
            self.assertIn("strict-transport-security", text)
            self.assertNotIn("Representative events", text)

    def test_results_renders_tcp_banner_summaries(self):
        """Protect results renders tcp banner summaries behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("network/tcp_banner 192.0.2.20:22", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="network/tcp_banner",
                values={},
            )
            runner.db.publish(
                "tcp.banner",
                {"host": "192.0.2.20", "port": 22, "protocol": "tcp", "banner": "SSH-2.0-OpenSSH"},
                "tcp_banner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: tcp.banner", text)
            self.assertIn("TCP banners", text)
            self.assertIn("SSH-2.0-OpenSSH", text)

    def test_results_renders_web_assessment_summaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("http_probe https://example.test | tls_probe | waf_detect", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="waf_detect",
                values={},
            )
            runner.db.publish(
                "service.detected",
                {"host": "example.test", "port": 443, "protocol": "tcp", "service": "https", "confidence": "high"},
                "service_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "tls.certificate",
                {"host": "example.test", "port": 443, "subject": "commonName=example.test", "issuer": "commonName=CA"},
                "tls_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "http.path",
                {"url": "https://example.test/.git/config", "host": "example.test", "port": 443, "path": "/.git/config", "status": 200, "interesting": True},
                "http_paths",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "web.waf.detected",
                {"url": "https://example.test/", "host": "example.test", "vendor": "Cloudflare", "confidence": "medium"},
                "waf_detect",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Services detected", text)
            self.assertIn("TLS certificates", text)
            self.assertIn("HTTP paths", text)
            self.assertIn("WAF signals", text)
            self.assertIn("Cloudflare", text)


if __name__ == "__main__":
    unittest.main()
