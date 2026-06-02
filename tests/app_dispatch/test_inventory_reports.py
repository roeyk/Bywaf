"""Tests for app inventory reports behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
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
    def test_inventory_commands_summarize_project_knowledge(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 192.0.2.0/24 | portscanner | http_probe", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="http_probe",
                values={},
            )
            runner.db.publish("host.found", {"host": "192.0.2.20", "name": "web-1", "status": "up"}, "hostscanner", pipeline_id="scan-pipeline", command_run_id="scan-step")
            runner.db.publish("name.resolved", {"name": "example.test", "host": "192.0.2.20"}, "dns_lookup", pipeline_id="scan-pipeline", command_run_id="scan-step")
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https"},
                "portscanner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "service.detected",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https", "product": "nginx"},
                "service_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "http.endpoint",
                {"url": "https://example.test/", "host": "192.0.2.20", "port": 443, "scheme": "https", "status": 200, "server": "nginx"},
                "http_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "http.path",
                {"url": "https://example.test/.git/config", "host": "192.0.2.20", "port": 443, "path": "/.git/config", "status": 200, "interesting": True},
                "http_paths",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "web.waf.detected",
                {"url": "https://example.test/", "host": "192.0.2.20", "vendor": "Cloudflare", "confidence": "medium"},
                "waf_detect",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "web.screenshotted_host",
                {"host": "192.0.2.20", "urls": ["https://example.test/"], "screenshots": [{"artifact_id": "artifact-1"}]},
                "screenshotter",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "smb.share.found",
                {"host": "192.0.2.20", "share": "Public", "access": "read", "authenticated": False, "remark": "guest"},
                "smb_shares",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "network.route.hop",
                {"target": "192.0.2.20", "hop": 1, "host": "gateway", "ip": "192.0.2.1", "rtt_ms": 1.2},
                "traceroute",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "tls.certificate",
                {"host": "192.0.2.20", "port": 443, "subject": "CN=example.test", "issuer": "CN=Test CA", "not_after": "2027-01-01"},
                "tls_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "tcp.banner",
                {"host": "192.0.2.20", "port": 22, "banner": "SSH-2.0-OpenSSH_9.6"},
                "tcp_banner",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "finding.candidate",
                {"title": "Missing HSTS", "class": "web.header.missing_hsts", "target_scope": {"kind": "web_origin", "value": "https://example.test/"}},
                "http_headers",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "hosts")
                dispatch_repl_line(runner, "services")
                dispatch_repl_line(runner, "web")
                dispatch_repl_line(runner, "shares")
                dispatch_repl_line(runner, "routes")
                dispatch_repl_line(runner, "certs")
                dispatch_repl_line(runner, "banners")
                dispatch_repl_line(runner, "paths")
                dispatch_repl_line(runner, "screenshots")

            text = output.getvalue()
            self.assertIn("Hosts: project inventory", text)
            self.assertIn("sorted by host ascending (use sort=-host to sort descending)", text)
            self.assertIn("192.0.2.20", text)
            self.assertIn("443/tcp https", text)
            self.assertIn("Services: project inventory", text)
            self.assertIn("nginx", text)
            self.assertIn("Web: project inventory", text)
            self.assertIn("https://example.test/", text)
            self.assertIn("Cloudflare", text)
            self.assertIn("Missing HSTS", text)
            self.assertIn("Shares: project inventory", text)
            self.assertIn("Public", text)
            self.assertIn("Routes: project inventory", text)
            self.assertIn("gateway", text)
            self.assertIn("Certificates: project inventory", text)
            self.assertIn("CN=example.test", text)
            self.assertIn("Banners: project inventory", text)
            self.assertIn("SSH-2.0-OpenSSH_9.6", text)
            self.assertIn("Paths: project inventory", text)
            self.assertIn("/.git/config", text)
            self.assertIn("Screenshots: project inventory", text)
            self.assertIn("artifact-1", text)

            sorted_output = io.StringIO()
            with contextlib.redirect_stdout(sorted_output):
                dispatch_repl_line(runner, "services sort=-port")
                dispatch_repl_line(runner, "web sort=status")
                dispatch_repl_line(runner, "routes sort=hop")

            sorted_text = sorted_output.getvalue()
            self.assertIn("sorted by port descending (use sort=port to sort ascending)", sorted_text)
            self.assertIn("sorted by status ascending (use sort=-status to sort descending)", sorted_text)
            self.assertIn("sorted by hop ascending (use sort=-hop to sort descending)", sorted_text)

    def test_inventory_new_filters_to_latest_new_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "status": "up"},
                "hostscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-host-step",
            )
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.10", "status": "up"},
                "hostscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-host-step",
            )
            runner.db.publish(
                "host.found",
                {"host": "192.0.2.20", "status": "up"},
                "hostscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-host-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 22, "protocol": "tcp", "service": "ssh"},
                "portscanner",
                pipeline_id="old-port-pipeline",
                command_run_id="old-port-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 22, "protocol": "tcp", "service": "ssh"},
                "portscanner",
                pipeline_id="new-port-pipeline",
                command_run_id="new-port-step",
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https"},
                "portscanner",
                pipeline_id="new-port-pipeline",
                command_run_id="new-port-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "hosts --new step=new-host-step")
                dispatch_repl_line(runner, "ports --new")

            text = output.getvalue()
            self.assertIn("Hosts: new in step=new-host-step", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10  ", text)
            self.assertIn("Ports: new since prior port inventory", text)
            self.assertIn("443/tcp https", text)
            self.assertNotIn("22/tcp ssh", text)

    def test_results_renders_route_hop_summaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("network/traceroute 192.0.2.20", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="network/traceroute",
                values={},
            )
            runner.db.publish(
                "network.route.hop",
                {"target": "192.0.2.20", "hop": 1, "host": "router", "ip": "192.0.2.1", "rtt_ms": 1.25, "status": "responded"},
                "traceroute",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "process.run",
                {"argv": ["traceroute", "192.0.2.20"], "returncode": 0, "stdout": "raw tool output"},
                "traceroute",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: network.route.hop", text)
            self.assertIn("Route hops", text)
            self.assertIn("192.0.2.1", text)
            self.assertIn("1.25 ms", text)
            self.assertNotIn("process.run", text)
            self.assertNotIn("Representative events", text)

    def test_results_renders_screenshots_smb_shares_and_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("web/screenshotter 192.0.2.20", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="web/screenshotter",
                values={},
            )
            runner.db.publish(
                "web.screenshotted_host",
                {
                    "host": "192.0.2.20",
                    "urls": ["http://192.0.2.20/"],
                    "screenshots": [{"artifact_id": "artifact-1"}],
                    "tool": "screenshotter",
                },
                "screenshotter",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "smb.share.found",
                {"host": "192.0.2.20", "share": "SYSVOL", "access": "read", "authenticated": True},
                "smb_probe",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )
            runner.db.publish(
                "artifact.attached",
                {
                    "artifact_id": "artifact-1",
                    "name": "192.0.2.20.png",
                    "content_type": "image/png",
                    "sha256": "a" * 64,
                    "size": 1200,
                },
                "screenshotter",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Shared schemas: artifact.attached, smb.share.found, web.screenshotted_host", text)
            self.assertIn("Screenshots", text)
            self.assertIn("artifact-1", text)
            self.assertIn("SMB shares", text)
            self.assertIn("SYSVOL", text)
            self.assertIn("Artifacts", text)
            self.assertIn("Inspect artifacts with: artifact list job=1", text)
            self.assertIn("192.0.2.20.png", text)
            self.assertNotIn("Representative events", text)

    def test_results_renders_tool_errors_with_artifact_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("nikto https://example.test/", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
                commandlet="nikto",
                values={},
            )
            runner.db.publish(
                "tool.error",
                {
                    "tool": "nikto",
                    "severity": "error",
                    "message": "nikto produced invalid JSON; raw output artifact attached",
                    "target": {"url": "https://example.test/"},
                    "artifact_id": "artifact-raw",
                    "artifact_row_id": 4,
                    "name": "nikto-example.json",
                    "content_type": "application/json",
                    "size": 8,
                },
                "nikto",
                pipeline_id="scan-pipeline",
                command_run_id="scan-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            text = output.getvalue()
            self.assertIn("Tool problems", text)
            self.assertIn("nikto produced invalid JSON", text)
            self.assertIn("#4 nikto-example.json", text)
            self.assertIn("applicat", text)
            self.assertIn("Inspect artifacts with: artifact show 4", text)
            self.assertNotIn("Representative events", text)

    def test_report_create_update_and_show_saved_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("git_expose_check http://example.test", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="pipeline-a",
                command_run_id="step-a",
                commandlet="git_expose_check",
                values={},
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "severity": "high",
                    "confidence": "high",
                    "target": {"url": "http://example.test/.git/config"},
                    "affected": [{"url": "http://example.test/.git/config"}],
                    "evidence": "git config returned",
                    "recommendation": "Block .git paths.",
                },
                "git_expose_check",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "title": "Missing X-Content-Type-Options",
                    "class": "web.header.missing_x_content_type_options",
                    "severity": "low",
                    "target": {"url": "http://second.example.test/"},
                    "target_scope": {"kind": "web_origin", "value": "http://second.example.test"},
                },
                "http_headers",
                pipeline_id="pipeline-b",
                command_run_id="step-b",
            )

            create_output = io.StringIO()
            with contextlib.redirect_stdout(create_output):
                dispatch_repl_line(runner, "report create name=client-a pipeline=pipeline-a")
            self.assertIn("saved report scope name=client-a", create_output.getvalue())

            show_output = io.StringIO()
            with contextlib.redirect_stdout(show_output):
                dispatch_repl_line(runner, "report show name=client-a")
            self.assertIn("Report scope: pipeline=pipeline-a", show_output.getvalue())
            self.assertIn("Exposed Git repository configuration", show_output.getvalue())

            update_output = io.StringIO()
            with contextlib.redirect_stdout(update_output):
                dispatch_repl_line(runner, "report update name=client-a pipeline=pipeline-a,pipeline-b")
            self.assertIn("pipeline=pipeline-a,pipeline-b", update_output.getvalue())

            updated_show_output = io.StringIO()
            with contextlib.redirect_stdout(updated_show_output):
                dispatch_repl_line(runner, "report show name=client-a")
            updated_text = updated_show_output.getvalue()
            self.assertIn("Report scope: pipeline=pipeline-a,pipeline-b", updated_text)
            self.assertIn("Exposed Git repository configuration", updated_text)
            self.assertIn("Missing X-Content-Type-Options", updated_text)


if __name__ == "__main__":
    unittest.main()
