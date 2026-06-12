"""TLS probe finding promotion tests.

Coverage focus: http tls probe findings regression behavior.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import dispatch_repl_line, make_runner, process_framework_requests
from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.http.tls_probe import tls_probe
from bywaf.repl import ShellState


class TlsProbeFindingTests(unittest.TestCase):
    """Groups regression coverage for tLS probe finding promotion tests."""
    def test_tls_probe_promotes_expired_certificate(self):
        """Protect tls probe promotes expired certificate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tls_probe", metadata={"capabilities": tls_probe.spec.capabilities})

            def fake_fetch(host, port, timeout):
                """Test helper for fake fetch."""
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
        """Protect TLS probe promotes hostname mismatch behavior from regressions."""
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

    def test_http_tls_alias_reports_tls_findings(self):
        """Protect HTTP TLS alias reports TLS findings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            output = io.StringIO()

            def fake_fetch(host, port, timeout):
                del host, port, timeout
                return {
                    "subject": "commonName=other.test",
                    "issuer": "commonName=CA",
                    "san": ["other.test"],
                    "not_after": "Jan 01 00:00:00 2035 GMT",
                }

            with (
                patch("bywaf.plugins.http.tls_probe.fetch_certificate", side_effect=fake_fetch),
                contextlib.redirect_stdout(output),
            ):
                runner.execute("http_tls example.test:443 | report status=all")
                process_framework_requests(runner, ShellState())

            self.assertTrue(runner.db.events_for_topic("job.requested")[-1].payload["command"].startswith("http_tls "))
            self.assertEqual(runner.db.events_for_topic("command.run.started")[0].payload["commandlet"], "tls_probe")
            self.assertEqual(
                [event.payload["class"] for event in runner.db.events_for_topic("finding.new")],
                ["service.tls.hostname_mismatch"],
            )
            self.assertIn("TLS certificate hostname mismatch", output.getvalue())

    def test_tls_probe_repl_output_is_compact(self):
        """Protect TLS probe REPL output is compact behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            state = ShellState()
            output = io.StringIO()

            def fake_fetch(host, port, timeout):
                del host, port, timeout
                return {
                    "subject": "commonName=example.test",
                    "issuer": "commonName=CA",
                    "san": ["example.test"],
                    "not_after": "Jan 01 00:00:00 2035 GMT",
                }

            with (
                patch("bywaf.plugins.http.tls_probe.fetch_certificate", side_effect=fake_fetch),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "tls_probe example.test:443", state)
                process_framework_requests(runner, state)

            text = output.getvalue()
            self.assertIn("tls.certificate example.test:443 subject=commonName=example.test", text)
            self.assertIn("captured TLS certificate from example.test:443", text)
            self.assertNotIn("{'subject':", text)
            self.assertNotIn("{'host':", text)


if __name__ == "__main__":
    unittest.main()
