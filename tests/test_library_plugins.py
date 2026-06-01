"""Tests for library plugins behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bywaf.artifacts import artifact_store_for_event_store
from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext, RunConfig
from bywaf.varstore import VarStore
from bywaf.plugins.analysis.yara_scan import YaraScan
from bywaf.plugins.identity.smb_probe import SmbProbe, safe_call, safe_shares
from bywaf.plugins.http.eyewitness import publish_screenshot, publish_screenshotted_hosts
from bywaf.plugins.http.screenshotter import Screenshotter
from bywaf.plugins.network.ssh_probe import SshProbe, ssh_targets
from bywaf.plugins.network.service_probe import service_probe
from bywaf.plugins.network.tcp_banner import banner_targets, probe_bytes, target_from_text, tcp_banner
from bywaf.plugins.network.traceroute import parse_traceroute_output, trace_targets, traceroute
from bywaf.plugins.http.http_paths import http_paths
from bywaf.plugins.http.tls_probe import tls_probe
from bywaf.plugins.http.waf_detect import waf_detect
from bywaf.plugins.recon.dns_enum import dns_enum
from bywaf.plugins.recon.dns_lookup import dns_lookup, optional_module
from bywaf.plugins.recon.shodan_lookup import ShodanLookup


class LibraryPluginTests(unittest.TestCase):
    def test_optional_module_publishes_tool_error_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test")
            with patch("importlib.import_module", side_effect=ImportError):
                self.assertIsNone(optional_module(context, "missing", "missing-lib"))
            self.assertEqual(db.events_for_topic("tool.error")[0].payload["tool"], "missing-lib")

    def test_dns_lookup_publishes_records(self):
        class FakeRecord:
            def to_text(self):
                return "127.0.0.1"

        class FakeResolver:
            def __init__(self):
                self.lifetime = 0
                self.timeout = 0
                self.nameservers = []

            def resolve(self, name, record_type):
                return [FakeRecord()]

        fake_dns = SimpleNamespace(Resolver=FakeResolver)
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="dns_lookup", metadata={"capabilities": dns_lookup.spec.capabilities})
            with patch("bywaf.plugins.recon.dns_lookup.optional_module", return_value=fake_dns):
                list(dns_lookup.run(context, ["record-type=A", "example.test"], []))
            record = db.events_for_topic("dns.record")[0].payload
            self.assertEqual(record["name"], "example.test")
            self.assertEqual(record["value"], "127.0.0.1")

    def test_dns_enum_publishes_name_and_host_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="dns_enum", metadata={"capabilities": dns_enum.spec.capabilities})
            with patch("bywaf.plugins.recon.dns_enum.resolve_name", return_value=["192.0.2.10"]):
                list(dns_enum.run(context, ["example.test"], []))
            self.assertEqual(db.events_for_topic("name.resolved")[0].payload["host"], "192.0.2.10")
            self.assertEqual(db.events_for_topic("host.found")[0].payload["name"], "example.test")

    def test_shodan_lookup_host_mode_publishes_host(self):
        fake_api = Mock()
        fake_api.host.return_value = {"ip_str": "8.8.8.8"}
        fake_shodan = SimpleNamespace(Shodan=Mock(return_value=fake_api))
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="shodan_lookup", metadata={"capabilities": ShodanLookup().spec.capabilities})
            with patch("bywaf.plugins.recon.shodan_lookup.optional_module", return_value=fake_shodan):
                list(ShodanLookup().run(context, ["api-key=key", "8.8.8.8"], []))
            self.assertEqual(db.events_for_topic("shodan.host")[0].payload["ip_str"], "8.8.8.8")

    def test_ssh_targets_use_explicit_hosts(self):
        self.assertEqual(ssh_targets(["host"], 2222, []), [("host", 2222)])

    def test_ssh_probe_publishes_failed_auth_without_real_network(self):
        class FakeClient:
            def set_missing_host_key_policy(self, policy):
                pass

            def connect(self, **kwargs):
                raise RuntimeError("auth failed")

            def close(self):
                pass

        fake_paramiko = SimpleNamespace(SSHClient=Mock(return_value=FakeClient()), AutoAddPolicy=Mock)
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="ssh_probe", metadata={"capabilities": SshProbe().spec.capabilities})
            with patch("bywaf.plugins.network.ssh_probe.optional_module", return_value=fake_paramiko):
                list(SshProbe().run(context, ["host"], []))
            self.assertEqual(db.events_for_topic("ssh.service")[0].payload["auth"], "failed")

    def test_tcp_banner_targets_use_port_open_events(self):
        targets = banner_targets(
            [],
            None,
            [
                Event.new("port.open", {"host": "192.0.2.10", "port": 22, "protocol": "tcp"}, "test"),
                Event.new("port.open", {"host": "192.0.2.10", "port": 53, "protocol": "udp"}, "test"),
            ],
        )
        self.assertEqual(targets[0].host, "192.0.2.10")
        self.assertEqual(targets[0].port, 22)

    def test_tcp_banner_parses_explicit_targets(self):
        self.assertEqual(target_from_text("192.0.2.10:2222", None).port, 2222)
        self.assertEqual(target_from_text("192.0.2.10", 22).port, 22)
        with self.assertRaisesRegex(ValueError, "require port="):
            target_from_text("192.0.2.10", None)

    def test_tcp_banner_http_head_probe_bytes(self):
        self.assertIn(b"HEAD / HTTP/1.0", probe_bytes("http-head", "example.test"))

    def test_tcp_banner_grabber_emits_schema_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tcp_banner", metadata={"capabilities": tcp_banner.spec.capabilities})
            with patch(
                "bywaf.plugins.network.tcp_banner.grab_tcp_banner",
                return_value={"banner": "SSH-2.0-Test", "elapsed_ms": 1},
            ):
                events = list(tcp_banner.run(context, ["192.0.2.10:22"], []))
            self.assertEqual(events[0]["host"], "192.0.2.10")
            self.assertEqual(events[0]["port"], 22)
            self.assertEqual(events[0]["protocol"], "tcp")
            self.assertEqual(events[0]["banner"], "SSH-2.0-Test")

    def test_service_probe_classifies_port_and_banner_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="service_probe", metadata={"capabilities": service_probe.spec.capabilities})
            events = [
                Event.new("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "portscanner"),
                Event.new("tcp.banner", {"host": "192.0.2.10", "port": 22, "protocol": "tcp", "banner": "SSH-2.0-Test"}, "tcp_banner"),
            ]
            list(service_probe.run(context, [], events))
            services = [event.payload["service"] for event in db.events_for_topic("service.detected")]
            self.assertEqual(services, ["https", "ssh"])

    def test_tls_probe_publishes_certificate_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tls_probe", metadata={"capabilities": tls_probe.spec.capabilities})
            with patch(
                "bywaf.plugins.http.tls_probe.fetch_certificate",
                return_value={"subject": "commonName=example.test", "issuer": "commonName=CA", "san": ["example.test"]},
            ):
                list(tls_probe.run(context, ["example.test:443"], []))
            cert = db.events_for_topic("tls.certificate")[0].payload
            self.assertEqual(cert["host"], "example.test")
            self.assertEqual(cert["subject"], "commonName=example.test")

    def test_tls_probe_requires_tls_1_2_or_newer(self):
        import importlib

        tls_probe_module = importlib.import_module("bywaf.plugins.http.tls_probe")

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def getpeercert(self):
                return {}

            def cipher(self):
                return None

            def version(self):
                return "TLSv1.2"

        class FakeContext:
            minimum_version = None

            def wrap_socket(self, raw, *, server_hostname):
                del raw, server_hostname
                return FakeSocket()

        fake_context = FakeContext()
        with (
            patch("bywaf.plugins.http.tls_probe.ssl.create_default_context", return_value=fake_context),
            patch("bywaf.plugins.http.tls_probe.socket.create_connection", return_value=FakeSocket()),
        ):
            tls_probe_module.fetch_certificate("example.test", 443, 5)

        self.assertEqual(fake_context.minimum_version, tls_probe_module.ssl.TLSVersion.TLSv1_2)

    def test_http_paths_publishes_path_and_finding_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="http_paths", metadata={"capabilities": http_paths.spec.capabilities})
            with patch(
                "bywaf.plugins.http.http_paths.probe_path",
                return_value={"status": 200, "content_type": "text/plain", "length": 42, "sample": "[core] repositoryformatversion = 0"},
            ):
                list(http_paths.run(context, ["paths=/.git/config", "http://127.0.0.1:8080"], []))
            path = db.events_for_topic("http.path")[0].payload
            self.assertTrue(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate")[0].payload["class"], "web.repo.git_config_exposed")

    def test_waf_detect_publishes_cloudflare_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="waf_detect", metadata={"capabilities": waf_detect.spec.capabilities})
            with patch("bywaf.plugins.http.waf_detect.fetch_headers", return_value={"status": 200, "headers": {"CF-Ray": "abc"}}):
                list(waf_detect.run(context, ["https://example.test/"], []))
            waf = db.events_for_topic("web.waf.detected")[0].payload
            self.assertEqual(waf["vendor"], "Cloudflare")

    def test_waf_detect_recognizes_aws_and_f5_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="waf_detect", metadata={"capabilities": waf_detect.spec.capabilities})
            responses = [
                {"status": 403, "headers": {"X-Amzn-Errortype": "ForbiddenException"}},
                {"status": 200, "headers": {"Set-Cookie": "BIGipServerpool=1", "X-WAF": "F5"}},
            ]
            with patch("bywaf.plugins.http.waf_detect.fetch_headers", side_effect=responses):
                list(waf_detect.run(context, ["https://aws.example.test/", "https://f5.example.test/"], []))
            vendors = [event.payload["vendor"] for event in db.events_for_topic("web.waf.detected")]
            self.assertEqual(vendors, ["AWS", "F5"])

    def test_http_paths_promotes_env_exposures(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="http_paths", metadata={"capabilities": http_paths.spec.capabilities})
            with patch(
                "bywaf.plugins.http.http_paths.probe_path",
                return_value={"status": 200, "content_type": "text/plain", "length": 20, "sample": "DATABASE_URL=postgres://x"},
            ):
                list(http_paths.run(context, ["paths=/.env", "http://127.0.0.1:8080"], []))
            finding = db.events_for_topic("finding.candidate")[0].payload
            self.assertEqual(finding["class"], "web.config.env_exposed")
            self.assertEqual(finding["severity"], "high")

    def test_traceroute_uses_host_found_input_events(self):
        targets = trace_targets(
            [],
            [
                Event.new("host.found", {"host": "192.0.2.10", "status": "up"}, "hostscanner"),
                Event.new("host.found", {"host": "192.0.2.10", "status": "up"}, "hostscanner"),
            ],
        )
        self.assertEqual(targets, ["192.0.2.10"])

    def test_traceroute_parser_handles_replies_and_timeouts(self):
        output = "\n".join(
            [
                "traceroute to example.test (192.0.2.20), 30 hops max",
                " 1  router.local (192.0.2.1)  1.123 ms  1.001 ms",
                " 2  * * *",
                " 3:  192.0.2.20  10.5ms",
            ]
        )
        hops = parse_traceroute_output("example.test", output)
        self.assertEqual(hops[0].hop, 1)
        self.assertEqual(hops[0].host, "router.local")
        self.assertEqual(hops[0].ip, "192.0.2.1")
        self.assertEqual(hops[0].rtt_ms, 1.123)
        self.assertEqual(hops[1].status, "timeout")
        self.assertEqual(hops[2].ip, "192.0.2.20")

    def test_traceroute_emits_route_hop_payloads(self):
        completed = SimpleNamespace(ok=True, stdout=" 1  router (192.0.2.1)  1.0 ms\n", stderr="", returncode=0)
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="traceroute", metadata={"capabilities": traceroute.spec.capabilities})
            with patch("bywaf.plugins.network.traceroute.run_traceroute", return_value=completed):
                events = list(traceroute.run(context, ["192.0.2.10"], []))
            self.assertEqual(events[0]["target"], "192.0.2.10")
            self.assertEqual(events[0]["hop"], 1)
            self.assertEqual(events[0]["ip"], "192.0.2.1")
            self.assertEqual(db.events_for_topic("host.found")[0].payload["host"], "192.0.2.10")

    def test_traceroute_falls_back_to_tracepath_when_default_binary_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="traceroute", metadata={"capabilities": traceroute.spec.capabilities})
            with patch(
                "bywaf.plugin.process.run_process_argv",
                side_effect=[
                    FileNotFoundError(2, "No such file or directory", "traceroute"),
                    subprocess.CompletedProcess(
                        ["tracepath", "-m", "30", "192.0.2.10"],
                        0,
                        " 1:  192.0.2.1  1.0ms\n",
                        "",
                    ),
                ],
            ) as run_process:
                events = list(traceroute.run(context, ["192.0.2.10"], []))
            self.assertEqual(run_process.call_count, 2)
            self.assertEqual(run_process.call_args_list[1].args[0][0], "tracepath")
            self.assertEqual(events[0]["ip"], "192.0.2.1")
            self.assertEqual(db.events_for_topic("tool.error"), [])

    def test_traceroute_reports_explicit_missing_binary_without_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="traceroute", metadata={"capabilities": traceroute.spec.capabilities})
            with patch(
                "bywaf.plugin.process.run_process_argv",
                side_effect=FileNotFoundError(2, "No such file or directory", "/missing/tool"),
            ) as run_process:
                events = list(traceroute.run(context, ["binary=/missing/tool", "192.0.2.10"], []))
            self.assertEqual(run_process.call_count, 1)
            self.assertEqual(events, [])
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["tool"], "/missing/tool")
            self.assertIn("missing external executable", error["message"])

    def test_manifest_config_uses_cli_vars_and_defaults(self):
        store = VarStore()
        store.set("tcp_banner.timeout", "1.5")
        context = CommandContext(db=None, source="tcp_banner", _varstore=store)
        parsed = tcp_banner.parse_manifest_args(context, ["port=22", "silent=true", "192.0.2.10"])
        cfg = RunConfig({name: getattr(parsed, name) for name in vars(parsed)})
        self.assertEqual(cfg.targets, ["192.0.2.10"])
        self.assertEqual(cfg.port, 22)
        self.assertTrue(cfg.silent)
        self.assertEqual(cfg.timeout, 1.5)
        self.assertEqual(cfg.read_bytes, 256)

    def test_manifest_config_is_per_run_immutable_snapshot(self):
        store = VarStore()
        store.set("tcp_banner.timeout", "1")
        context = CommandContext(db=None, source="tcp_banner", _varstore=store)
        parsed = tcp_banner.parse_manifest_args(context, [])
        cfg = RunConfig({name: getattr(parsed, name) for name in vars(parsed)})
        store.set("tcp_banner.timeout", "9")
        self.assertEqual(cfg.timeout, 1.0)
        with self.assertRaisesRegex(AttributeError, "immutable"):
            cfg.timeout = 2.0

    def test_smb_helpers_tolerate_metadata_errors(self):
        bad = Mock()
        bad.getServerName.side_effect = RuntimeError("nope")
        bad.listShares.side_effect = RuntimeError("denied")
        self.assertEqual(safe_call(bad, "getServerName"), "")
        self.assertEqual(safe_shares(bad), [])

    def test_smb_probe_publishes_server_metadata(self):
        fake_conn = Mock()
        fake_conn.getServerName.return_value = "SERVER"
        fake_conn.getServerDomain.return_value = "DOMAIN"
        fake_conn.getServerOS.return_value = "Windows"
        fake_conn.listShares.return_value = [{"shi1_netname": "IPC$\x00"}]
        fake_smb = SimpleNamespace(SMBConnection=Mock(return_value=fake_conn))
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="smb_probe", metadata={"capabilities": SmbProbe().spec.capabilities})
            with patch("bywaf.plugins.identity.smb_probe.optional_module", return_value=fake_smb):
                list(SmbProbe().run(context, ["host"], []))
            payload = db.events_for_topic("smb.server")[0].payload
            self.assertEqual(payload["server_name"], "SERVER")
            self.assertEqual(payload["shares"], ["IPC$"])

    def test_screenshotter_uses_eyewitness_artifact_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="screenshotter", metadata={"capabilities": Screenshotter().spec.capabilities})
            output_dir = Path(tmp, "eyewitness")
            output_dir.mkdir()
            screenshot = output_dir / "site.png"
            screenshot.write_bytes(b"\x89PNG\r\n\x1a\n")

            payload = publish_screenshot(context, screenshot, output_dir, [{"url": "http://127.0.0.1/"}], silent=True)
            publish_screenshotted_hosts(context, [payload])

            artifacts = artifact_store_for_event_store(db).list(command_run_id=context.command_run_id)
            self.assertEqual(len(artifacts), 1)
            screenshot_event = db.events_for_topic("web.screenshotted_host")[0]
            self.assertEqual(screenshot_event.payload["urls"], ["http://127.0.0.1/"])
            self.assertEqual(screenshot_event.payload["host"], "")
            self.assertEqual(screenshot_event.payload["screenshots"][0]["artifact_id"], artifacts[0].artifact_id)
            self.assertEqual(db.events_for_topic("eyewitness.screenshot")[0].source, "screenshotter")

    def test_yara_scan_publishes_matches(self):
        fake_rules = Mock()
        fake_rules.match.return_value = [SimpleNamespace(rule="webshell", namespace="default", tags=["php"])]
        fake_yara = SimpleNamespace(compile=Mock(return_value=fake_rules))
        with tempfile.TemporaryDirectory() as tmp:
            rule = Path(tmp, "rules.yar")
            target = Path(tmp, "shell.php")
            rule.write_text("rule webshell { condition: true }")
            target.write_text("<?php")
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="yara_scan", metadata={"capabilities": YaraScan().spec.capabilities})
            with patch("bywaf.plugins.analysis.yara_scan.optional_module", return_value=fake_yara):
                list(YaraScan().run(context, [f"rule={rule}", str(target)], []))
            self.assertEqual(db.events_for_topic("yara.match")[0].payload["rule"], "webshell")


if __name__ == "__main__":
    unittest.main()
