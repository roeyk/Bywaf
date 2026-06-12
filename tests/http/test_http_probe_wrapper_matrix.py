"""Fixture-backed HTTP probe wrapper coverage.

Coverage focus: http http probe wrapper matrix regression behavior.
"""

from __future__ import annotations

import io
import tempfile
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.http.probe import HttpProbe, probe_url
from bywaf.plugins.http.tls_probe import tls_probe
from bywaf.plugins.http.waf_detect import waf_detect


class FakeHttpResponse:
    """Minimal urllib response fixture."""

    status = 200
    reason = "OK"
    headers = {"Server": "nginx", "Content-Type": "text/html"}

    def __init__(self, body: bytes = b"<title>Fixture</title>") -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        """Test helper for read."""
        del size
        return self.body

    def geturl(self) -> str:
        return "https://example.test/final"


class FakeOpener:
    """Test double used by this module's regression cases."""
    def __init__(self, result) -> None:
        self.result = result

    def open(self, request, timeout: float):
        del request, timeout
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class HttpProbeWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed HTTP probe wrapper coverage."""
    def test_probe_url_extracts_success_metadata(self):
        result = probe_url(FakeOpener(FakeHttpResponse()), "https://example.test/", "GET", 5, "Bywaf/0.9")

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["server"], "nginx")
        self.assertEqual(result["title"], "Fixture")
        self.assertEqual(result["final_url"], "https://example.test/final")

    def test_probe_url_treats_http_error_as_response_metadata(self):
        headers = Message()
        headers["Server"] = "cloudflare"
        headers["Content-Type"] = "text/html"
        error = urllib.error.HTTPError(
            "https://example.test/admin",
            403,
            "Forbidden",
            headers,
            io.BytesIO(b"<title>Denied</title>"),
        )

        result = probe_url(FakeOpener(error), "https://example.test/admin", "GET", 5, "Bywaf/0.9")

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 403)
        self.assertEqual(result["server"], "cloudflare")
        self.assertEqual(result["title"], "Denied")

    def test_http_probe_preserves_url_error_as_endpoint_payload(self):
        error = urllib.error.URLError("connection refused")
        context = CommandContext(db=None, source="http_probe")

        with patch("bywaf.plugins.http.probe.build_opener", return_value=FakeOpener(error)):
            events = list(HttpProbe().run(context, ["https://example.test/"], []))

        self.assertFalse(events[0]["ok"])
        self.assertEqual(events[0]["error"], "connection refused")
        self.assertEqual(events[0]["host"], "example.test")

    def test_waf_detect_ignores_fetch_errors_without_false_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="waf_detect", metadata={"capabilities": waf_detect.spec.capabilities})

            with patch("bywaf.plugins.http.waf_detect.fetch_headers", return_value={"error": "timeout", "headers": {}}):
                list(waf_detect.run(context, ["https://example.test/"], []))

            self.assertEqual(db.events_for_topic("web.waf.detected"), [])

    def test_tls_probe_emits_error_event_without_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tls_probe", metadata={"capabilities": tls_probe.spec.capabilities})

            with patch("bywaf.plugins.http.tls_probe.fetch_certificate", side_effect=OSError("handshake failed")):
                list(tls_probe.run(context, ["example.test:443"], []))

            error = db.events_for_topic("tls.probe.error")[0].payload
            self.assertEqual(error["host"], "example.test")
            self.assertIn("handshake failed", error["error"])
            self.assertEqual(db.events_for_topic("tls.certificate"), [])


class WafFetchHeaderTests(TestCase):
    """Groups regression coverage for fixture-backed HTTP probe wrapper coverage."""
    def test_unsupported_url_scheme_returns_error_fixture(self):
        from bywaf.plugins.http.waf_detect import fetch_headers

        result = fetch_headers("file:///tmp/x", 5, "Bywaf/0.9")

        self.assertEqual(result["error"], "unsupported URL scheme")
        self.assertEqual(result["headers"], {})
