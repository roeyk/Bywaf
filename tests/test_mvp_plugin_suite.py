"""Tests for the first useful MVP pentest plugin chain.

Provides fixture-backed coverage for Bywaf's discovery-to-report workflow
without live internet dependencies.

Used by:
- pytest and CI: keep the bundled plugin suite composable.
- maintainers: document the expected event flow through the MVP chain.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, process_framework_requests
from bywaf.plugins.network.nmap_backend import NmapPort


class MvpPluginSuiteTests(unittest.TestCase):
    def test_discovery_to_report_mvp_chain_uses_fixtures(self):
        """Run the MVP pentest chain using local fake tool responses."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))

            def fake_probe_url(opener, url, method, timeout, user_agent):
                del opener, timeout, user_agent
                return {
                    "ok": True,
                    "status": 200,
                    "reason": "OK",
                    "final_url": url,
                    "elapsed_ms": 2,
                    "headers": {
                        "Server": "nginx",
                        "Content-Type": "text/html",
                        "X-Powered-By": "PHP/8.3",
                    },
                    "server": "nginx",
                    "content_type": "text/html",
                    "title": "Index of /" if method == "GET" else "",
                }

            def fake_run_process(argv, *, cwd=None, env=None, timeout=None):
                del cwd, env, timeout
                output_path = Path(argv[argv.index("-output") + 1])
                output_path.write_text(
                    json.dumps(
                        {
                            "host": "192.0.2.20",
                            "vulnerabilities": [
                                {
                                    "id": "999001",
                                    "msg": "Missing X-Frame-Options header",
                                    "url": "/",
                                    "method": "GET",
                                    "severity": "low",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, stdout="fixture nikto ok", stderr="")

            output = io.StringIO()
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.0.2.20"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.20", 80, "tcp", "open", "http", "syn-ack")],
                ),
                patch("bywaf.plugins.http.http_probe.probe_url", side_effect=fake_probe_url),
                patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run_process),
                contextlib.redirect_stdout(output),
            ):
                runner.execute(
                    "hostscanner 192.0.2.20 | portscanner port=80 | "
                    "http_probe --method GET | webfin | nikto --source webfin"
                )
                process_framework_requests(runner, ShellState())
                runner.execute("finding_dedupe")
                process_framework_requests(runner, ShellState())
                runner.execute("report status=all")
                process_framework_requests(runner, ShellState())

            topics = set(runner.db.topics())
            for topic in (
                "host.found",
                "port.open",
                "http.endpoint",
                "web.fingerprint",
                "nikto.finding",
                "vulnerability.potential",
                "artifact.attached",
                "finding.new",
                "report.rendered",
            ):
                with self.subTest(topic=topic):
                    self.assertIn(topic, topics)

            finding = runner.db.events_for_topic("finding.new")[0].payload
            self.assertEqual(finding["title"], "Missing X-Frame-Options header")
            self.assertIn("Missing X-Frame-Options header", output.getvalue())


if __name__ == "__main__":
    unittest.main()
