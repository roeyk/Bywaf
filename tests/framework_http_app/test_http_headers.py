"""Framework HTTP app tests for test http headers."""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import dispatch_repl_line, make_runner, process_framework_requests
from bywaf.event import Event
from bywaf.plugins.http.headers import HttpHeaders
from bywaf.plugins.http.headers.findings import missing_sec_headers
from bywaf.plugins.http.headers.models import HeaderProbeResult, HeaderTarget
from bywaf.repl import ShellState


class TestHttpHeadersTests(unittest.TestCase):
    """HTTP header commandlet tests with network-free connection fakes.

    The suite checks both direct helper logic and app/REPL behavior so compact
    console output, event publication, and finding promotion stay aligned.
    """

    def test_http_headers_targets_from_arg(self):
        targets = HttpHeaders().targets("example.test", None, False, [])
        self.assertEqual(targets, [("example.test", 80, False)])

    def test_http_headers_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpHeaders().targets(None, None, False, [event])
        self.assertEqual(targets, [("127.0.0.1", 443, True)])

    def test_http_headers_promotes_missing_security_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.headers.detect.http.client.HTTPSConnection", FakeHttpConnection):
                runner.execute("http_headers --ssl true example.test")

            candidates = runner.db.events_for_topic("finding.candidate")
            titles = {event.payload["title"] for event in candidates}
            self.assertEqual(
                titles,
                {
                    "Missing Content-Security-Policy",
                    "Missing HTTP Strict Transport Security",
                    "Missing Referrer-Policy",
                    "Missing X-Content-Type-Options",
                    "Missing browser framing protection",
                },
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))

    def test_http_headers_repl_output_is_compact(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()

            with (
                patch("bywaf.plugins.http.headers.detect.http.client.HTTPSConnection", FakeHttpConnection),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "http_headers --ssl true example.test", state)
                process_framework_requests(runner, state)

            text = output.getvalue()
            # The REPL should show concise event summaries, not raw nested
            # dictionaries from headers or finding payloads.
            self.assertIn("finding.candidate Missing HTTP Strict Transport Security", text)
            self.assertIn("http.headers example.test:443 status=200 headers=Server", text)
            self.assertNotIn("{'affected':", text)
            self.assertNotIn("{'headers':", text)

    def test_http_headers_promotes_cookie_redirect_and_server_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.http.headers.detect.http.client.HTTPSConnection",
                WeakHeaderConnection,
            ):
                runner.execute("http_headers --ssl true example.test")

            classes = {event.payload["class"] for event in runner.db.events_for_topic("finding.candidate")}
            self.assertIn("web.cookie.missing_secure", classes)
            self.assertIn("web.cookie.missing_httponly", classes)
            self.assertIn("web.cookie.missing_samesite", classes)
            self.assertIn("web.header.server_disclosure", classes)
            self.assertIn("web.redirect.https_to_http", classes)

    def test_http_headers_promotes_missing_framing_policy(self):
        result = HeaderProbeResult(
            target=HeaderTarget("example.test", 443, True),
            status=200,
            headers={"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff"},
        )

        classes = {candidate["class"] for candidate in missing_sec_headers(result)}

        self.assertIn("web.header.missing_framing_policy", classes)

    def test_http_headers_accepts_csp_frame_ancestors_as_framing_policy(self):
        result = HeaderProbeResult(
            target=HeaderTarget("example.test", 443, True),
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            },
        )

        classes = {candidate["class"] for candidate in missing_sec_headers(result)}

        self.assertNotIn("web.header.missing_framing_policy", classes)

    def test_http_headers_accepts_x_frame_options_as_framing_policy(self):
        result = HeaderProbeResult(
            target=HeaderTarget("example.test", 443, True),
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

        classes = {candidate["class"] for candidate in missing_sec_headers(result)}

        self.assertNotIn("web.header.missing_framing_policy", classes)

    def test_http_headers_promotes_missing_csp_and_referrer_policy(self):
        result = HeaderProbeResult(
            target=HeaderTarget("example.test", 443, True),
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

        classes = {candidate["class"] for candidate in missing_sec_headers(result)}

        self.assertIn("web.header.missing_content_security_policy", classes)
        self.assertIn("web.header.missing_referrer_policy", classes)

    def test_http_headers_accepts_csp_and_referrer_policy(self):
        result = HeaderProbeResult(
            target=HeaderTarget("example.test", 443, True),
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "strict-origin-when-cross-origin",
            },
        )

        classes = {candidate["class"] for candidate in missing_sec_headers(result)}

        self.assertNotIn("web.header.missing_content_security_policy", classes)
        self.assertNotIn("web.header.missing_referrer_policy", classes)


if __name__ == "__main__":
    unittest.main()


class FakeHostResult:
    """Test double used by this module's regression cases."""
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakeHttpResponse:
    """HEAD response with only the attributes consumed by the plugin."""

    status = 200
    headers = {"Server": "example"}


class FakeHttpConnection:
    """http.client connection fake used to avoid network calls."""

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path):
        self.method = method
        self.path = path

    def getresponse(self):
        return FakeHttpResponse()

    def close(self):
        return None


class WeakHeaderResponse:
    """Response intentionally missing security headers and cookie flags."""

    status = 302
    headers = {
        "Server": "Apache/2.4.58",
        "Set-Cookie": "sid=abc123; Path=/",
        "Location": "http://example.test/login",
    }


class WeakHeaderConnection(FakeHttpConnection):
    """Connection fake returning weak header posture."""

    def getresponse(self):
        return WeakHeaderResponse()


class FakePortScanner:
    """Legacy fake retained for older target-resolution helper tests."""

    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    """Test double used by this module's regression cases."""
    PortScanner = FakePortScanner
