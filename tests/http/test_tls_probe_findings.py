"""TLS probe finding promotion tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.http.tls_probe import tls_probe


class TlsProbeFindingTests(unittest.TestCase):
    def test_tls_probe_promotes_expired_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tls_probe", metadata={"capabilities": tls_probe.spec.capabilities})

            def fake_fetch(host, port, timeout):
                del host, port, timeout
                return {
                    "subject": "commonName=example.test",
                    "issuer": "commonName=CA",
                    "san": ["example.test"],
                    "not_after": "Jan 01 00:00:00 2020 GMT",
                }

            with patch("bywaf.plugins.http.tls_probe.fetch_certificate", side_effect=fake_fetch):
                list(tls_probe.run(context, ["example.test:443"], []))

            finding = db.events_for_topic("finding.candidate")[0].payload
            self.assertEqual(finding["class"], "service.tls.certificate_expired")
            self.assertEqual(finding["target"]["host"], "example.test")

    def test_tls_probe_promotes_hostname_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tls_probe", metadata={"capabilities": tls_probe.spec.capabilities})

            def fake_fetch(host, port, timeout):
                del host, port, timeout
                return {
                    "subject": "commonName=other.test",
                    "issuer": "commonName=CA",
                    "san": ["other.test"],
                    "not_after": "Jan 01 00:00:00 2035 GMT",
                }

            with patch("bywaf.plugins.http.tls_probe.fetch_certificate", side_effect=fake_fetch):
                list(tls_probe.run(context, ["example.test:443"], []))

            finding = db.events_for_topic("finding.candidate")[0].payload
            self.assertEqual(finding["class"], "service.tls.hostname_mismatch")
            self.assertIn("example.test", finding["evidence"])


if __name__ == "__main__":
    unittest.main()
