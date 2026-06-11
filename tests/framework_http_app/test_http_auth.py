"""Framework HTTP app tests for HTTP auth posture inspection."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import make_runner
from bywaf.event import Event
from bywaf.plugins.http.auth import (
    AuthTarget,
    HttpAuth,
    auth_findings,
    challenge_realms,
    normalize_schemes,
    probe_auth,
)


class TestHttpAuthTests(unittest.TestCase):
    """HTTP authentication posture tests with network-free connection fakes.

    The suite verifies target derivation, challenge parsing, weak-auth finding
    promotion, and commandlet event publication.
    """

    def test_http_auth_targets_from_arg(self):
        targets = HttpAuth().targets(["example.test:8080"], "auto", "/admin", [])
        self.assertEqual(targets, [("example.test", 8080, "http", "/admin")])

    def test_http_auth_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpAuth().targets([], "auto", "/login", [event])
        self.assertEqual(targets, [("127.0.0.1", 443, "https", "/login")])

    def test_http_auth_normalizes_schemes_and_realms(self):
        challenges = ['Basic realm="Admin"', 'Digest realm="Users", nonce="abc"']

        self.assertEqual(normalize_schemes(challenges), ["BASIC", "DIGEST"])
        self.assertEqual(challenge_realms(challenges), ["Admin", "Users"])

    def test_http_auth_promotes_basic_over_http_admin_and_missing_realm(self):
        payload = {
            "url": "http://example.test/admin",
            "host": "example.test",
            "port": 80,
            "scheme": "http",
            "path": "/admin",
            "auth_present": True,
            "schemes": ["BASIC"],
            "realms": [],
        }

        classes = {candidate["class"] for candidate in auth_findings(payload)}

        self.assertEqual(
            classes,
            {
                "web.auth.admin_challenge_observed",
                "web.auth.basic_missing_realm",
                "web.auth.basic_over_cleartext",
            },
        )

    def test_http_auth_probe_reads_www_authenticate_header(self):
        target = AuthTarget("https://example.test/admin", "example.test", 443, "https", "/admin")
        with patch("bywaf.plugins.http.auth.http.client.HTTPSConnection", BasicConnection):
            result = probe_auth(target, method="HEAD", timeout=2)

        self.assertEqual(result["status"], 401)
        self.assertEqual(result["schemes"], ["BASIC"])
        self.assertEqual(result["realms"], ["Admin"])

    def test_http_auth_probe_reads_proxy_authenticate_header(self):
        target = AuthTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.auth.http.client.HTTPConnection", ProxyConnection):
            result = probe_auth(target, method="HEAD", timeout=2)

        self.assertEqual(result["schemes"], ["NEGOTIATE"])

    def test_http_auth_probe_returns_error_payload(self):
        target = AuthTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.auth.http.client.HTTPConnection", ErrorConnection):
            result = probe_auth(target, method="HEAD", timeout=2)

        self.assertFalse(result["ok"])
        self.assertEqual(result["schemes"], [])
        self.assertIn("connection refused", str(result["error"]))

    def test_http_auth_runner_publishes_fact_and_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.auth.http.client.HTTPConnection", RiskyConnection):
                runner.execute("http_auth http://example.test/admin")

            auth_events = runner.db.events_for_topic("http.auth")
            candidates = runner.db.events_for_topic("finding.candidate")

            self.assertEqual(len(auth_events), 1)
            self.assertEqual(auth_events[0].payload["schemes"], ["BASIC"])
            self.assertEqual(auth_events[0].payload["realms"], [])
            self.assertEqual(
                {event.payload["class"] for event in candidates},
                {
                    "web.auth.admin_challenge_observed",
                    "web.auth.basic_missing_realm",
                    "web.auth.basic_over_cleartext",
                },
            )
            self.assertTrue(all(event.pipeline_id for event in candidates))


class FakeResponse:
    """Base auth response fake exposing the http.client response surface used."""

    status = 401
    reason = "Unauthorized"
    headers: list[tuple[str, str]] = []

    def getheaders(self):
        return self.headers


class BasicResponse(FakeResponse):
    headers = [("WWW-Authenticate", 'Basic realm="Admin"')]


class ProxyResponse(FakeResponse):
    status = 407
    reason = "Proxy Authentication Required"
    headers = [("Proxy-Authenticate", "Negotiate")]


class RiskyResponse(FakeResponse):
    headers = [("WWW-Authenticate", "Basic")]


class BasicConnection:
    """http.client connection fake returning an authentication challenge."""

    response = BasicResponse()

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


class ProxyConnection(BasicConnection):
    response = ProxyResponse()


class RiskyConnection(BasicConnection):
    response = RiskyResponse()


class ErrorConnection(BasicConnection):
    """Connection fake for transport failure payload tests."""

    def request(self, method, path):
        raise OSError("connection refused")


if __name__ == "__main__":
    unittest.main()
