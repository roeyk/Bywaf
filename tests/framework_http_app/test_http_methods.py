"""Framework HTTP app tests for HTTP method inspection.

Coverage focus: framework http app http methods regression behavior.
"""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import make_runner, process_framework_requests
from bywaf.event import Event
from bywaf.plugins.http.methods import (
    HttpMethods,
    MethodTarget,
    method_findings,
    normalize_methods,
    probe_methods,
)
from bywaf.repl import ShellState


class TestHttpMethodsTests(unittest.TestCase):
    """HTTP method commandlet tests with network-free response fakes.

    These tests cover target resolution, OPTIONS probing, finding promotion,
    dedupe/report integration, and implicit analysis via `| report`.
    """

    def test_http_methods_targets_from_arg(self):
        """Protect http methods targets from arg behavior from regressions."""
        targets = HttpMethods().targets(["example.test:8080"], "auto", "/admin", [])
        self.assertEqual(targets, [("example.test", 8080, "http", "/admin")])

    def test_http_methods_targets_from_events(self):
        """Protect HTTP methods targets from events behavior from regressions."""
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpMethods().targets([], "auto", "/", [event])
        self.assertEqual(targets, [("127.0.0.1", 443, "https", "/")])

    def test_http_methods_normalizes_allow_header(self):
        """Protect HTTP methods normalizes allow header behavior from regressions."""
        self.assertEqual(
            normalize_methods("get, POST, options, TRACE, PROPFIND"),
            ["GET", "OPTIONS", "POST", "PROPFIND", "TRACE"],
        )

    def test_http_methods_promotes_trace_write_and_webdav_methods(self):
        """Protect HTTP methods promotes trace write and webdav methods behavior from regressions."""
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
        """Protect HTTP methods probe uses allow header behavior from regressions."""
        target = MethodTarget("https://example.test/", "example.test", 443, "https", "/")
        with patch("bywaf.plugins.http.methods.http.client.HTTPSConnection", AllowConnection):
            result = probe_methods(target, timeout=2)

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["methods"], ["GET", "OPTIONS", "TRACE"])

    def test_http_methods_probe_uses_public_header_fallback(self):
        """Protect HTTP methods probe uses public header fallback behavior from regressions."""
        target = MethodTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.methods.http.client.HTTPConnection", PublicConnection):
            result = probe_methods(target, timeout=2)

        self.assertEqual(result["methods"], ["GET", "OPTIONS"])

    def test_http_methods_probe_returns_error_payload(self):
        """Protect HTTP methods probe returns error payload behavior from regressions."""
        target = MethodTarget("http://example.test/", "example.test", 80, "http", "/")
        with patch("bywaf.plugins.http.methods.http.client.HTTPConnection", ErrorConnection):
            result = probe_methods(target, timeout=2)

        self.assertFalse(result["ok"])
        self.assertEqual(result["methods"], [])
        self.assertIn("connection refused", str(result["error"]))

    def test_http_methods_runner_publishes_fact_and_findings(self):
        """Protect HTTP methods runner publishes fact and findings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.methods.http.client.HTTPSConnection", RiskyConnection):
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

    def test_http_methods_deduped_findings_appear_in_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.http.methods.http.client.HTTPSConnection", RiskyConnection):
                runner.execute("http_methods https://example.test/ | finding_dedupe -s")

            findings = runner.db.events_for_topic("finding.new")
            self.assertEqual(
                {event.payload["class"] for event in findings},
                {
                    "web.method.trace_enabled",
                    "web.method.webdav_enabled",
                    "web.method.write_methods_enabled",
                },
            )

            output = io.StringIO()
            pipeline_id = findings[0].pipeline_id
            with contextlib.redirect_stdout(output):
                # This verifies the explicit chain: scanner -> dedupe -> report.
                runner.execute(f"report pipeline={pipeline_id} status=all")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("HTTP TRACE method enabled", text)
            self.assertIn("HTTP write-capable methods enabled", text)
            self.assertIn("WebDAV HTTP methods enabled", text)

    def test_http_methods_report_pipeline_implies_dedupe_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch("bywaf.plugins.http.methods.http.client.HTTPSConnection", RiskyConnection),
                contextlib.redirect_stdout(output),
            ):
                # This verifies the short user-facing chain: scanner -> report,
                # where report implies the passive finding dedupe analysis step.
                runner.execute("http_methods https://example.test/ | report status=all")
                process_framework_requests(runner, ShellState())

            self.assertEqual(
                {event.payload["class"] for event in runner.db.events_for_topic("finding.new")},
                {
                    "web.method.trace_enabled",
                    "web.method.webdav_enabled",
                    "web.method.write_methods_enabled",
                },
            )
            text = output.getvalue()
            self.assertIn("HTTP TRACE method enabled", text)
            self.assertIn("HTTP write-capable methods enabled", text)
            self.assertIn("WebDAV HTTP methods enabled", text)


class FakeResponse:
    """Base OPTIONS response fake."""

    status = 200
    reason = "OK"
    headers: dict[str, str] = {}

    def getheader(self, name):
        return self.headers.get(name, "")


class AllowResponse(FakeResponse):
    """Test double used by this module's regression cases."""
    headers = {"Allow": "GET, OPTIONS, TRACE"}


class PublicResponse(FakeResponse):
    """Test double used by this module's regression cases."""
    headers = {"Public": "GET, OPTIONS"}


class RiskyResponse(FakeResponse):
    """Test double used by this module's regression cases."""
    headers = {"Allow": "GET, OPTIONS, PUT, PROPFIND, TRACE"}


class AllowConnection:
    """http.client connection fake returning a configurable response."""

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
    """Test double used by this module's regression cases."""
    response = PublicResponse()


class RiskyConnection(AllowConnection):
    """Test double used by this module's regression cases."""
    response = RiskyResponse()


class ErrorConnection(AllowConnection):
    """Connection fake for transport failure payload tests."""

    def request(self, method, path):
        raise OSError("connection refused")


if __name__ == "__main__":
    unittest.main()
