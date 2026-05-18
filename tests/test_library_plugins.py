import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.yara_scan import YaraScan
from bywaf.plugins.identity.smb_probe import SmbProbe, safe_call, safe_shares
from bywaf.plugins.network.ssh_probe import SshProbe, ssh_targets
from bywaf.plugins.recon.dns_lookup import DnsLookup, optional_module
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
            context = CommandContext(db=db, source="dns_lookup", metadata={"capabilities": DnsLookup().spec.capabilities})
            with patch("bywaf.plugins.recon.dns_lookup.optional_module", return_value=fake_dns):
                list(DnsLookup().run(context, ["record-type=A", "example.test"], []))
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
