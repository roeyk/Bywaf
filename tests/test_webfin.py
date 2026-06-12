"""Tests for webfin behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples.

Coverage focus: webfin regression behavior.
"""

import contextlib
import io
import unittest
from unittest.mock import patch

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.webfin import (
    WebFingerprint,
    endpoint_payloads,
    fingerprint_endpoint,
    infer_technologies,
)


class WebFingerprintTests(unittest.TestCase):
    """Groups regression coverage for webfin behavior."""
    def test_fingerprint_endpoint_infers_technology_and_observations(self):
        """Protect fingerprint endpoint infers technology and observations behavior from regressions."""
        payload = fingerprint_endpoint(
            {
                "url": "https://example.test/",
                "host": "example.test",
                "port": 443,
                "scheme": "https",
                "status": 200,
                "server": "nginx",
                "content_type": "text/html",
                "title": "Index of /",
                "headers": {"X-Powered-By": "PHP/8.3"},
            }
        )
        self.assertIn("nginx", payload["technologies"])
        self.assertIn("php", payload["technologies"])
        kinds = {observation["kind"] for observation in payload["observations"]}
        self.assertIn("directory-listing", kinds)
        self.assertIn("powered-by", kinds)

    def test_infer_technologies_deduplicates(self):
        """Protect infer technologies deduplicates behavior from regressions."""
        self.assertEqual(infer_technologies("nginx nginx", "", "", {}), ["nginx"])

    def test_endpoint_payloads_use_http_endpoint_events(self):
        event = Event.new(
            "http.endpoint",
            {"url": "http://127.0.0.1/", "host": "127.0.0.1", "port": 80, "status": 200},
            "test",
        )
        payloads = endpoint_payloads([], [event], 5, "Bywaf/0.9", CommandContext(None, "webfin"))
        self.assertEqual(payloads[0]["url"], "http://127.0.0.1/")

    def test_endpoint_payloads_probe_explicit_targets(self):
        context = CommandContext(None, "webfin")
        with patch("bywaf.plugins.http.webfin.probe_url", return_value={"ok": True, "status": 200}) as probe:
            payloads = endpoint_payloads(["example.test:8080"], [], 5, "Bywaf/0.9", context)
        self.assertEqual(payloads[0]["url"], "http://example.test:8080/")
        self.assertEqual(probe.call_args.args[2], "GET")

    def test_webfin_emits_payload_and_alert(self):
        context = CommandContext(db=None, source="webfin", metadata={"command_run_id": "run-1"})
        event = Event.new(
            "http.endpoint",
            {
                "url": "http://127.0.0.1/",
                "host": "127.0.0.1",
                "port": 80,
                "status": 200,
                "server": "Apache",
            },
            "test",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            events = list(WebFingerprint().run(context, [], [event]))
        self.assertEqual(events[0]["url"], "http://127.0.0.1/")
        self.assertIn("apache", events[0]["technologies"])
        self.assertIn("webfin <run-1>: fingerprinted", output.getvalue())

    def test_webfin_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="webfin", metadata={"command_run_id": "run-1"})
        event = Event.new("http.endpoint", {"url": "http://127.0.0.1/"}, "test")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            list(WebFingerprint().run(context, ["-s"], [event]))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
