"""Tests for the first useful MVP pentest plugin chain.

Provides fixture-backed coverage for Bywaf's discovery-to-report workflow
without live internet dependencies.

Used by:
- pytest and CI: keep the bundled plugin suite composable.
- maintainers: document the expected event flow through the MVP chain.

Coverage focus: mvp plugin suite regression behavior.
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
from bywaf.plugins.http.repo_exposure import DetectionStatus, base_result
from bywaf.registry import PluginRegistry


class MvpPluginSuiteTests(unittest.TestCase):
    """Groups regression coverage for the first useful MVP pentest plugin chain."""
    def test_mvp_chain_specs_stay_composable_after_manifest_hydration(self):
        """Keep the documented MVP chain wired by hydrated sidecar metadata."""
        registry = PluginRegistry.discover()
        hostscanner = registry.get("hostscanner").spec
        portscanner = registry.get("portscanner").spec
        http_probe = registry.get("http_probe").spec
        webfin = registry.get("webfin").spec
        nikto = registry.get("nikto").spec

        self.assertIn("host.found", hostscanner.emits)
        self.assertIn("host.found", portscanner.consumes)
        self.assertIn("port.open", portscanner.emits)
        self.assertIn("port.open", http_probe.consumes)
        self.assertIn("http.endpoint", http_probe.emits)
        self.assertIn("http.endpoint", webfin.consumes)
        self.assertIn("web.fingerprint", webfin.emits)
        self.assertIn("web.fingerprint", nikto.consumes)
        for spec in (hostscanner, portscanner, http_probe, webfin, nikto):
            with self.subTest(commandlet=spec.name):
                self.assertIn("network.connect", spec.capabilities)

    def test_mvp_chain_prunes_out_of_scope_hosts_before_downstream_scan(self):
        """Keep the demo pentest chain inside the configured network scope."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.registry.varstore.set("global.policy.network.allow", "192.0.2.0/24")

            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.0.2.20"]) as discover,
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.20", 80, "tcp", "open", "http", "syn-ack")],
                ) as scan_ports,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                runner.execute("hostscanner 192.0.2.20 198.51.100.20 --yes | portscanner port=80")
                process_framework_requests(runner, ShellState())

            discover.assert_called_once_with("192.0.2.20", "-sn")
            scan_ports.assert_called_once()
            self.assertEqual(scan_ports.call_args.args[0], ["192.0.2.20"])
            hosts = [event.payload["host"] for event in runner.db.events_for_topic("host.found")]
            self.assertEqual(hosts, ["192.0.2.20"])
            repair = runner.db.events_for_topic("plan.repair.applied")[0]
            self.assertEqual(repair.payload["repair"], "prune-out-of-scope")
            self.assertEqual(repair.payload["after"], {"targets": ["192.0.2.20"]})

    def test_mvp_downstream_replay_ignores_stale_http_endpoints(self):
        """Keep replayed downstream checks scoped to the selected pipeline."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "http.endpoint",
                {
                    "url": "http://198.51.100.20/",
                    "host": "198.51.100.20",
                    "port": 80,
                    "scheme": "http",
                },
                "fixture",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            checked_urls: list[str] = []

            def fake_probe_url(opener, url, method, timeout, user_agent):
                """Test helper for fake probe url."""
                del opener, method, timeout, user_agent
                return {
                    "ok": True,
                    "status": 200,
                    "reason": "OK",
                    "final_url": url,
                    "elapsed_ms": 2,
                    "headers": {"Server": "nginx"},
                    "server": "nginx",
                    "content_type": "text/html",
                    "title": "",
                }

            def fake_probe_git_config(opener, endpoint, *, timeout, user_agent):
                """Test helper for fake probe git config."""
                del opener, timeout, user_agent
                checked_url = f"{endpoint['url'].rstrip('/')}/.git/config"
                checked_urls.append(checked_url)
                return base_result(
                    endpoint,
                    checked_url,
                    DetectionStatus.CANDIDATE,
                    http_status=200,
                    evidence="[core]\n\trepositoryformatversion = 0\n",
                )

            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.0.2.20"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.20", 80, "tcp", "open", "http", "syn-ack")],
                ),
                patch("bywaf.plugins.http.probe.probe_url", side_effect=fake_probe_url),
                patch("bywaf.plugins.http.repo_exposure.command.probe_git_config", side_effect=fake_probe_git_config),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                endpoint_events = runner.execute("hostscanner 192.0.2.20 | portscanner port=80 | http_probe --method GET")
                process_framework_requests(runner, ShellState())
                pipeline_id = endpoint_events[0].pipeline_id
                runner.execute(f"repo_exposure --from pipeline={pipeline_id} topic=http.endpoint")
                process_framework_requests(runner, ShellState())

            self.assertEqual(checked_urls, ["http://192.0.2.20/.git/config"])
            exposure_events = runner.db.events_for_topic("repo.git_config.checked")
            self.assertEqual(len(exposure_events), 1)
            self.assertNotEqual(exposure_events[0].pipeline_id, "old-pipeline")
            self.assertEqual(exposure_events[0].payload["url"], "http://192.0.2.20/")

    def test_discovery_to_report_mvp_chain_uses_fixtures(self):
        """Run the MVP pentest chain using local fake tool responses."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            bundle_export = Path(tmp, "client-a.bundle.json")
            screenshot_output = Path(tmp, "eyewitness")
            stale_finding = runner.db.publish(
                "finding.new",
                {
                    "finding_id": "legacy-finding",
                    "title": "Legacy admin panel exposure",
                    "target": {"host": "198.51.100.20"},
                    "severity": "high",
                },
                "fixture",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.publish(
                "web.fingerprint",
                {"url": "https://stale.example.test/", "interesting": True},
                "fixture",
            )
            nikto_targets: list[str] = []

            def fake_probe_url(opener, url, method, timeout, user_agent):
                """Test helper for fake probe url."""
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

            def fake_probe_path(url, timeout, user_agent):
                del timeout, user_agent
                if url.endswith("/.git/config"):
                    return {
                        "status": 200,
                        "content_type": "text/plain",
                        "length": 35,
                        "sample": "[core] repositoryformatversion = 0",
                    }
                return {"status": 404, "content_type": "text/plain", "length": 0, "sample": ""}

            def fake_probe_git_config(opener, endpoint, *, timeout, user_agent):
                del opener, timeout, user_agent
                checked_url = f"{endpoint['url'].rstrip('/')}/.git/config"
                return base_result(
                    endpoint,
                    checked_url,
                    DetectionStatus.CANDIDATE,
                    http_status=200,
                    evidence="[core]\n\trepositoryformatversion = 0\n",
                )

            def fake_run_process(argv, *, cwd=None, env=None, timeout=None):
                del cwd, env, timeout
                if "--web" in argv:
                    screenshot_dir = Path(argv[argv.index("-d") + 1]) / "screens"
                    screenshot_dir.mkdir(parents=True, exist_ok=True)
                    Path(screenshot_dir, "mvp.png").write_bytes(b"png")
                    return subprocess.CompletedProcess(argv, 0, stdout="fixture eyewitness ok", stderr="")

                nikto_targets.append(argv[argv.index("-host") + 1])
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
                patch("bywaf.plugins.http.probe.probe_url", side_effect=fake_probe_url),
                patch("bywaf.plugins.http.paths.probe_path", side_effect=fake_probe_path),
                patch("bywaf.plugins.http.repo_exposure.command.probe_git_config", side_effect=fake_probe_git_config),
                patch(
                    "bywaf.plugins.http.tls_probe.fetch_certificate",
                    return_value={"subject": "commonName=example.test", "issuer": "commonName=CA", "san": ["example.test"]},
                ),
                patch("bywaf.plugins.http.waf_detect.fetch_headers", return_value={"status": 200, "headers": {"CF-Ray": "abc"}}),
                patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run_process),
                contextlib.redirect_stdout(output),
            ):
                endpoint_events = runner.execute("hostscanner 192.0.2.20 | portscanner port=80 | http_probe --method GET")
                process_framework_requests(runner, ShellState())
                pipeline_id = endpoint_events[0].pipeline_id
                runner.execute(f"service_probe --from pipeline={pipeline_id} topic=http.endpoint")
                process_framework_requests(runner, ShellState())
                runner.execute(f"http_paths --from pipeline={pipeline_id} topic=http.endpoint paths=/.git/config")
                process_framework_requests(runner, ShellState())
                runner.execute(f"repo_exposure --from pipeline={pipeline_id} topic=http.endpoint")
                process_framework_requests(runner, ShellState())
                runner.execute(f"waf_detect --from pipeline={pipeline_id} topic=http.endpoint")
                process_framework_requests(runner, ShellState())
                runner.execute(
                    f"screenshotter --from pipeline={pipeline_id} topic=http.endpoint "
                    f"output-dir={screenshot_output} --silent"
                )
                process_framework_requests(runner, ShellState())
                screenshot_pipeline_id = runner.db.events_for_topic("eyewitness.screenshot")[0].pipeline_id
                runner.execute(f"webfin --from pipeline={pipeline_id} topic=http.endpoint | nikto --source webfin")
                process_framework_requests(runner, ShellState())
                nikto_pipeline_id = runner.db.events_for_topic("nikto.finding")[0].pipeline_id
                runner.execute("tls_probe example.test:443 | service_probe")
                process_framework_requests(runner, ShellState())
                runner.execute("finding_dedupe")
                process_framework_requests(runner, ShellState())
                runner.execute("report status=all")
                process_framework_requests(runner, ShellState())
                runner.execute(f"note add pipeline={pipeline_id} text=client approved MVP evidence bundle")
                process_framework_requests(runner, ShellState())
                runner.execute("bundle create name=client-a")
                process_framework_requests(runner, ShellState())
                runner.execute(f"bundle add name=client-a audit pipeline={pipeline_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"bundle add name=client-a evidence pipeline={screenshot_pipeline_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"bundle add name=client-a evidence pipeline={nikto_pipeline_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"bundle export name=client-a file={bundle_export}")
                process_framework_requests(runner, ShellState())

            topics = set(runner.db.topics())
            for topic in (
                "host.found",
                "port.open",
                "http.endpoint",
                "service.detected",
                "http.path",
                "repo.git_config.checked",
                "web.waf.detected",
                "tls.certificate",
                "web.fingerprint",
                "eyewitness.screenshot",
                "web.screenshotted_host",
                "nikto.finding",
                "vulnerability.potential",
                "artifact.attached",
                "finding.new",
                "report.rendered",
                "note.attached",
                "bundle.created",
                "bundle.item.added",
                "bundle.exported",
            ):
                with self.subTest(topic=topic):
                    self.assertIn(topic, topics)

            finding_titles = [event.payload["title"] for event in runner.db.events_for_topic("finding.new")]
            self.assertIn("Missing X-Frame-Options header", finding_titles)
            self.assertIn("Exposed Git repository configuration", finding_titles)
            self.assertEqual(nikto_targets, ["http://192.0.2.20/"])
            exposure_events = runner.db.events_for_topic("repo.git_config.checked")
            self.assertEqual(exposure_events[0].payload["family"], "repo_exposure")
            self.assertEqual(exposure_events[0].payload["status"], "candidate")
            screenshot_events = runner.db.events_for_topic("eyewitness.screenshot")
            self.assertEqual(screenshot_events[0].payload["relative_path"], "screens/mvp.png")
            screenshotted = runner.db.events_for_topic("web.screenshotted_host")[0].payload
            self.assertEqual(screenshotted["urls"], ["http://192.0.2.20/"])
            self.assertIn("Missing X-Frame-Options header", output.getvalue())
            self.assertNotIn("Legacy admin panel exposure", output.getvalue())
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertNotIn(stale_finding.id, rendered.payload["events"])
            notes = runner.db.events_for_topic("note.attached")
            self.assertEqual(notes[0].pipeline_id, pipeline_id)
            self.assertEqual(notes[0].payload["note"], "client approved MVP evidence bundle")
            bundle = json.loads(bundle_export.read_text(encoding="utf-8"))
            self.assertEqual(bundle["format"], "bywaf.bundle.v1")
            self.assertEqual(bundle["name"], "client-a")
            self.assertEqual([item["kind"] for item in bundle["items"]], ["audit", "evidence", "evidence"])
            audit_records = bundle["items"][0]["records"]
            self.assertTrue(audit_records)
            self.assertTrue(all(record["pipeline_id"] == pipeline_id for record in audit_records))
            self.assertNotIn("legacy-finding", json.dumps(bundle, sort_keys=True))
            evidence_records = bundle["items"][1]["records"]
            self.assertTrue(evidence_records)
            self.assertTrue(all(record["pipeline_id"] == screenshot_pipeline_id for record in evidence_records))
            self.assertTrue(all(record["commandlet"] == "screenshotter" for record in evidence_records))
            self.assertTrue(all("body_base64" in record for record in evidence_records))
            nikto_evidence_records = bundle["items"][2]["records"]
            self.assertTrue(nikto_evidence_records)
            self.assertTrue(all(record["pipeline_id"] == nikto_pipeline_id for record in nikto_evidence_records))
            self.assertTrue(all(record["commandlet"] == "nikto" for record in nikto_evidence_records))
            self.assertTrue(all("body_base64" in record for record in nikto_evidence_records))


if __name__ == "__main__":
    unittest.main()
