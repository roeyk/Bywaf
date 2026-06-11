"""Tests for the WafW00f wrapped-process plugin."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext, ProcessResult
from bywaf.plugins.http.wafw00f import Waf, parse_wafw00f_output


def process_result(stdout: str, *, returncode: int = 0, stderr: str = "") -> ProcessResult:
    """Build a framework process result for patched WafW00f runs.

    Called by: tests that patch `ContextProcess.run()` and need a realistic
    return object without launching the external binary.
    """
    return ProcessResult(("wafw00f", "https://example.test/"), returncode, stdout, stderr)


class WafW00fPluginTests(unittest.TestCase):
    """Exercise WafW00f wrapper parsing and event publication.

    These tests intentionally patch the framework process service rather than
    WafW00f internals. That keeps the wrapper contract realistic while staying
    network-free and independent of whether `wafw00f` is installed locally.
    """

    def context(self, tmp: str) -> tuple[EventStore, CommandContext]:
        """Return a DB-backed command context with the wrapper's capabilities."""
        db = EventStore(Path(tmp, "bywaf.sqlite3"))
        # Use a real EventStore so assertions observe the same event write path
        # operators use in normal commandlet execution.
        context = CommandContext(db, source="waf", metadata={"capabilities": Waf().spec.capabilities})
        return db, context

    def test_parser_extracts_wafw00f_detection(self):
        """The parser should capture vendor/product from common WafW00f output."""
        signal = parse_wafw00f_output(
            "The site https://example.test/ is behind Cloudflare (Cloudflare Inc.) WAF.\n"
        )

        self.assertIsNotNone(signal)
        assert signal is not None
        self.assertEqual(signal.vendor, "Cloudflare")
        self.assertEqual(signal.product, "Cloudflare Inc.")
        self.assertEqual(signal.confidence, "high")

    def test_parser_ignores_no_waf_output(self):
        """Negative WafW00f output should not create a detection signal."""
        self.assertIsNone(parse_wafw00f_output("No WAF detected by the generic detection\n"))

    def test_explicit_target_publishes_detection(self):
        """A direct target should run once and persist a `web.waf.detected` fact."""
        output = "The site https://example.test/ is behind Cloudflare (Cloudflare Inc.) WAF.\n"
        with tempfile.TemporaryDirectory() as tmp:
            db, context = self.context(tmp)
            with patch("bywaf.plugin.process.ContextProcess.run", return_value=process_result(output)):
                list(Waf().run(context, ["https://example.test/"], []))

            detection = db.events_for_topic("web.waf.detected")[0].payload

        self.assertEqual(detection["url"], "https://example.test/")
        self.assertEqual(detection["host"], "example.test")
        self.assertEqual(detection["vendor"], "Cloudflare")
        self.assertEqual(detection["product"], "Cloudflare Inc.")
        self.assertEqual(detection["scanner"], "wafw00f")

    def test_pipeline_endpoint_target_publishes_detection(self):
        """An upstream `http.endpoint` event should be accepted as target input."""
        output = "The site https://example.test/ is behind ModSecurity WAF.\n"
        endpoint = Event.new(
            "http.endpoint",
            {"url": "https://example.test/login", "host": "example.test", "port": 443, "scheme": "https"},
            "http_probe",
        )
        with tempfile.TemporaryDirectory() as tmp:
            db, context = self.context(tmp)
            with patch("bywaf.plugin.process.ContextProcess.run", return_value=process_result(output)):
                list(Waf().run(context, [], [endpoint]))

            detection = db.events_for_topic("web.waf.detected")[0].payload

        self.assertEqual(detection["url"], "https://example.test/login")
        self.assertEqual(detection["vendor"], "ModSecurity")

    def test_no_waf_output_emits_no_detection(self):
        """A clean WafW00f result should leave the detection topic empty."""
        with tempfile.TemporaryDirectory() as tmp:
            db, context = self.context(tmp)
            with patch(
                "bywaf.plugin.process.ContextProcess.run",
                return_value=process_result("No WAF detected by the generic detection\n"),
            ):
                list(Waf().run(context, ["https://example.test/"], []))

            self.assertEqual(db.events_for_topic("web.waf.detected"), [])

    def test_missing_binary_publishes_tool_error(self):
        """Missing external binary should be reported as structured `tool.error`."""
        with tempfile.TemporaryDirectory() as tmp:
            db, context = self.context(tmp)
            with patch("bywaf.plugin.process.ContextProcess.run", side_effect=FileNotFoundError("wafw00f")):
                list(Waf().run(context, ["https://example.test/"], []))

            error = db.events_for_topic("tool.error")[0].payload

        self.assertEqual(error["tool"], "wafw00f")
        self.assertEqual(error["url"], "https://example.test/")
        self.assertIn("not found", error["error"])
