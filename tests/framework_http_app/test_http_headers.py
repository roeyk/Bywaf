"""Framework HTTP app tests for test http headers."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import make_runner
from bywaf.event import Event
from bywaf.plugins.http.http_headers import HttpHeaders


class TestHttpHeadersTests(unittest.TestCase):
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
            with patch("bywaf.plugins.http.http_headers.detect.http.client.HTTPSConnection", FakeHttpConnection):
                runner.execute("http_headers --ssl true example.test")

            candidates = runner.db.events_for_topic("finding.candidate")
            titles = {event.payload["title"] for event in candidates}
            self.assertEqual(
                titles,
                {"Missing HTTP Strict Transport Security", "Missing X-Content-Type-Options"},
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))

    def test_http_headers_promotes_cookie_redirect_and_server_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.http.http_headers.detect.http.client.HTTPSConnection",
                WeakHeaderConnection,
            ):
                runner.execute("http_headers --ssl true example.test")

            classes = {event.payload["class"] for event in runner.db.events_for_topic("finding.candidate")}
            self.assertIn("web.cookie.missing_secure", classes)
            self.assertIn("web.cookie.missing_httponly", classes)
            self.assertIn("web.cookie.missing_samesite", classes)
            self.assertIn("web.header.server_disclosure", classes)
            self.assertIn("web.redirect.https_to_http", classes)


if __name__ == "__main__":
    unittest.main()


class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakeHttpResponse:
    status = 200
    headers = {"Server": "example"}


class FakeHttpConnection:
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
    status = 302
    headers = {
        "Server": "Apache/2.4.58",
        "Set-Cookie": "sid=abc123; Path=/",
        "Location": "http://example.test/login",
    }


class WeakHeaderConnection(FakeHttpConnection):
    def getresponse(self):
        return WeakHeaderResponse()


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
