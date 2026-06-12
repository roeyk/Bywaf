"""Framework HTTP app tests for HTTP CORS posture inspection."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import make_runner
from bywaf.event import Event
from bywaf.plugins.http.cors import (
    CorsTarget,
    HttpCors,
    cors_findings,
    probe_cors,
)


class TestHttpCorsTests(unittest.TestCase):
    """Groups regression coverage for framework HTTP app tests for HTTP CORS posture inspection."""
    def test_http_cors_targets_from_arg(self):
        targets = HttpCors().targets(["example.test:8080"], "auto", "/api", [])
        self.assertEqual(targets, [("example.test", 8080, "http", "/api")])

    def test_http_cors_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpCors().targets([], "auto", "/api", [event])
        self.assertEqual(targets, [("127.0.0.1", 443, "https", "/api")])

    def test_http_cors_probe_reads_response_headers(self):
        target = CorsTarget("https://example.test/api", "example.test", 443, "https", "/api")
        with patch("bywaf.plugins.http.cors.http.client.HTTPSConnection", ReflectedConnection):
            result = probe_cors(
                target,
                origin="https://evil.example",
                request_method="GET",
                timeout=2,
            )

        self.assertEqual(result["status"], 204)
        self.assertEqual(result["allow_origin"], "https://evil.example")
        self.assertTrue(result["reflected_origin"])
        self.assertTrue(result["credentials_allowed"])

    def test_http_cors_probe_returns_error_payload(self):
        target = CorsTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.cors.http.client.HTTPConnection", ErrorConnection):
            result = probe_cors(
                target,
                origin="https://evil.example",
                request_method="GET",
                timeout=2,
            )

        self.assertFalse(result["ok"])
        self.assertIn("connection refused", str(result["error"]))

    def test_http_cors_promotes_reflected_origin_with_credentials(self):
        payload = {
            "url": "https://example.test/api",
            "host": "example.test",
            "port": 443,
            "scheme": "https",
            "path": "/api",
            "origin": "https://evil.example",
            "allow_origin": "https://evil.example",
            "allow_credentials": "true",
            "reflected_origin": True,
            "wildcard_origin": False,
            "credentials_allowed": True,
        }

        findings = cors_findings(payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["class"], "web.cors.arbitrary_origin_with_credentials")

    def test_http_cors_promotes_wildcard_with_credentials(self):
        payload = {
            "url": "https://example.test/api",
            "host": "example.test",
            "port": 443,
            "scheme": "https",
            "path": "/api",
            "origin": "https://evil.example",
            "allow_origin": "*",
            "allow_credentials": "true",
            "reflected_origin": False,
            "wildcard_origin": True,
            "credentials_allowed": True,
        }

        findings = cors_findings(payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["class"], "web.cors.wildcard_with_credentials")

    def test_http_cors_runner_publishes_fact_and_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.cors.http.client.HTTPSConnection", ReflectedConnection):
                runner.execute("http_cors https://example.test/api origin=https://evil.example")

            cors_events = runner.db.events_for_topic("http.cors")
            candidates = runner.db.events_for_topic("finding.candidate")

            self.assertEqual(len(cors_events), 1)
            self.assertTrue(cors_events[0].payload["reflected_origin"])
            self.assertEqual(
                [event.payload["class"] for event in candidates],
                ["web.cors.arbitrary_origin_with_credentials"],
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))


class FakeResponse:
    """Test double used by this module's regression cases."""
    status = 204
    reason = "No Content"
    headers: dict[str, str] = {}

    def getheader(self, name):
        return self.headers.get(name, "")


class ReflectedResponse(FakeResponse):
    """Test double used by this module's regression cases."""
    headers = {
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST",
        "Vary": "Origin",
    }


class ReflectedConnection:
    """Test double used by this module's regression cases."""
    response = ReflectedResponse()

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, headers=None):
        self.method = method
        self.path = path
        self.headers = headers or {}

    def getresponse(self):
        return self.response

    def close(self):
        return None


class ErrorConnection(ReflectedConnection):
    """Test double used by this module's regression cases."""
    def request(self, method, path, headers=None):
        raise OSError("connection refused")


if __name__ == "__main__":
    unittest.main()
