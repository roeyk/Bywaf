"""Framework HTTP app tests for HTTP method inspection."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import make_runner
from bywaf.event import Event
from bywaf.plugins.http.http_methods import (
    HttpMethods,
    MethodTarget,
    method_findings,
    normalize_methods,
    probe_methods,
)


class TestHttpMethodsTests(unittest.TestCase):
    def test_http_methods_targets_from_arg(self):
        targets = HttpMethods().targets(["example.test:8080"], "auto", "/admin", [])
        self.assertEqual(targets, [("example.test", 8080, "http", "/admin")])

    def test_http_methods_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpMethods().targets([], "auto", "/", [event])
        self.assertEqual(targets, [("127.0.0.1", 443, "https", "/")])

    def test_http_methods_normalizes_allow_header(self):
        self.assertEqual(
            normalize_methods("get, POST, options, TRACE, PROPFIND"),
            ["GET", "OPTIONS", "POST", "PROPFIND", "TRACE"],
        )

    def test_http_methods_promotes_trace_write_and_webdav_methods(self):
        payload = {
            "url": "https://example.test/",
            "host": "example.test",
            "port": 443,
            "scheme": "https",
            "path": "/",
            "methods": ["GET", "PUT", "PROPFIND", "TRACE"],
        }

        classes = {candidate["class"] for candidate in method_findings(payload)}

        self.assertEqual(
            classes,
            {
                "web.method.trace_enabled",
                "web.method.webdav_enabled",
                "web.method.write_methods_enabled",
            },
        )

    def test_http_methods_probe_uses_allow_header(self):
        target = MethodTarget("https://example.test/", "example.test", 443, "https", "/")
        with patch("bywaf.plugins.http.http_methods.http.client.HTTPSConnection", AllowConnection):
            result = probe_methods(target, timeout=2)

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["methods"], ["GET", "OPTIONS", "TRACE"])

    def test_http_methods_probe_uses_public_header_fallback(self):
        target = MethodTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.http_methods.http.client.HTTPConnection", PublicConnection):
            result = probe_methods(target, timeout=2)

        self.assertEqual(result["methods"], ["GET", "OPTIONS"])

    def test_http_methods_probe_returns_error_payload(self):
        target = MethodTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.http_methods.http.client.HTTPConnection", ErrorConnection):
            result = probe_methods(target, timeout=2)

        self.assertFalse(result["ok"])
        self.assertEqual(result["methods"], [])
        self.assertIn("connection refused", str(result["error"]))

    def test_http_methods_runner_publishes_fact_and_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.http_methods.http.client.HTTPSConnection", RiskyConnection):
                runner.execute("http_methods https://example.test/")

            method_events = runner.db.events_for_topic("http.methods")
            candidates = runner.db.events_for_topic("finding.candidate")

            self.assertEqual(len(method_events), 1)
            self.assertEqual(method_events[0].payload["methods"], ["GET", "OPTIONS", "PROPFIND", "PUT", "TRACE"])
            self.assertEqual(
                {event.payload["class"] for event in candidates},
                {
                    "web.method.trace_enabled",
                    "web.method.webdav_enabled",
                    "web.method.write_methods_enabled",
                },
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))


class FakeResponse:
    status = 200
    reason = "OK"
    headers: dict[str, str] = {}

    def getheader(self, name):
        return self.headers.get(name, "")


class AllowResponse(FakeResponse):
    headers = {"Allow": "GET, OPTIONS, TRACE"}


class PublicResponse(FakeResponse):
    headers = {"Public": "GET, OPTIONS"}


class RiskyResponse(FakeResponse):
    headers = {"Allow": "GET, OPTIONS, PUT, PROPFIND, TRACE"}


class AllowConnection:
    response = AllowResponse()

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path):
        self.method = method
        self.path = path

    def getresponse(self):
        return self.response

    def close(self):
        return None


class PublicConnection(AllowConnection):
    response = PublicResponse()


class RiskyConnection(AllowConnection):
    response = RiskyResponse()


class ErrorConnection(AllowConnection):
    def request(self, method, path):
        raise OSError("connection refused")


if __name__ == "__main__":
    unittest.main()
