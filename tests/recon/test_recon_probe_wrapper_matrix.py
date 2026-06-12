"""Fixture-backed recon probe wrapper coverage.

Coverage focus: recon recon probe wrapper matrix regression behavior.
"""

from __future__ import annotations

import socket
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.recon.dns_enum import dns_enum
from bywaf.plugins.recon.dns_lookup import dns_lookup
from bywaf.plugins.recon.shodan_lookup import ShodanLookup


class DnsWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed recon probe wrapper coverage."""
    def test_dns_lookup_preserves_resolver_failure_as_dns_error(self):
        """Protect dns lookup preserves resolver failure as dns error behavior from regressions."""
        class FakeResolver:
            lifetime = 0
            timeout = 0
            nameservers = []

            def resolve(self, name, record_type):
                del name, record_type
                raise RuntimeError("NXDOMAIN")

        fake_dns = SimpleNamespace(Resolver=FakeResolver)

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="dns_lookup", metadata={"capabilities": dns_lookup.spec.capabilities})

            with patch("bywaf.plugins.recon.dns_lookup.optional_module", return_value=fake_dns):
                list(dns_lookup.run(context, ["example.test"], []))

            error = db.events_for_topic("dns.error")[0].payload
            self.assertEqual(error["name"], "example.test")
            self.assertEqual(error["record_type"], "A")
            self.assertIn("NXDOMAIN", error["error"])

    def test_dns_enum_preserves_resolution_failure_as_dns_error(self):
        """Protect dns enum preserves resolution failure as dns error behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="dns_enum", metadata={"capabilities": dns_enum.spec.capabilities})

            with patch("bywaf.plugins.recon.dns_enum.resolve_name", side_effect=socket.gaierror("not found")):
                list(dns_enum.run(context, ["missing.example.test"], []))

            error = db.events_for_topic("dns.error")[0].payload
            self.assertEqual(error["name"], "missing.example.test")
            self.assertIn("not found", error["error"])
            self.assertEqual(db.events_for_topic("host.found"), [])


class ShodanWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed recon probe wrapper coverage."""
    def test_shodan_lookup_publishes_missing_api_key_error(self):
        """Protect shodan lookup publishes missing API key error behavior from regressions."""
        fake_shodan = SimpleNamespace(Shodan=Mock())

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="shodan_lookup", metadata={"capabilities": ShodanLookup().spec.capabilities})

            with patch("bywaf.plugins.recon.shodan_lookup.optional_module", return_value=fake_shodan):
                list(ShodanLookup().run(context, ["8.8.8.8"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["tool"], "shodan")
            self.assertEqual(error["message"], "missing Shodan API key")

    def test_shodan_lookup_preserves_api_failure_as_tool_error(self):
        fake_api = Mock()
        fake_api.host.side_effect = RuntimeError("quota exceeded")
        fake_shodan = SimpleNamespace(Shodan=Mock(return_value=fake_api))

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="shodan_lookup", metadata={"capabilities": ShodanLookup().spec.capabilities})

            with patch("bywaf.plugins.recon.shodan_lookup.optional_module", return_value=fake_shodan):
                list(ShodanLookup().run(context, ["api-key=key", "8.8.8.8"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["tool"], "shodan")
            self.assertIn("quota exceeded", error["message"])
