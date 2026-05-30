"""Tests for library plugins behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bywaf.artifacts import artifact_store_for_event_store
from bywaf.db import EventStore
from bywaf.events import Event
from bywaf.plugin import CommandContext, RunConfig
from bywaf.varstore import VarStore
from bywaf.plugins.analysis.yara_scan import YaraScan
from bywaf.plugins.identity.smb_probe import SmbProbe, safe_call, safe_shares
from bywaf.plugins.http.eyewitness import publish_screenshot, publish_screenshotted_hosts
from bywaf.plugins.http.screenshotter import Screenshotter
from bywaf.plugins.network.ssh_probe import SshProbe, ssh_targets
from bywaf.plugins.network.tcp_banner import banner_targets, probe_bytes, target_from_text, tcp_banner
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
