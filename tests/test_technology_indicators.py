"""Tests for passive technology/version indicator findings."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.technology_indicators import findings_from_event, technology_indicators


class TechnologyIndicatorsTests(unittest.TestCase):
    def test_apache_httpd_249_server_header_becomes_version_indicator(self):
        event = Event.new(
            "http.endpoint",
            {
                "url": "https://example.test/",
                "host": "example.test",
                "port": 443,
                "scheme": "https",
                "server": "Apache/2.4.49 (Unix)",
            },
            "test",
        )

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])

        self.assertEqual(finding["class"], "technology.version.apache_httpd_2_4_49_indicator")
        self.assertEqual(finding["confidence"], "medium")
        self.assertEqual(finding["confidence_basis"], "version_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2021-41773"]})
        self.assertEqual(finding["finding_scope"], "web_origin")
        self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertIn("passive http.endpoint evidence", finding["evidence"])

    def test_apache_httpd_250_banner_becomes_service_indicator(self):
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp", "banner": "Server: Apache/2.4.50"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.apache_httpd_2_4_50_indicator")
        self.assertEqual(finding["confidence_basis"], "version_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2021-42013"]})
        self.assertEqual(finding["finding_scope"], "service")
        self.assertEqual(finding["target_scope"], {"kind": "service", "value": "192.0.2.10:80/tcp"})

    def test_web_fingerprint_match_uses_fingerprint_basis(self):
        event = Event.new(
            "web.fingerprint",
            {
                "url": "http://example.test/",
                "host": "example.test",
                "port": 80,
                "scheme": "http",
                "server": "Apache/2.4.49",
                "technologies": ["apache"],
            },
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["confidence_basis"], "fingerprint_indicator")

    def test_unlisted_apache_version_is_not_promoted(self):
        event = Event.new(
            "http.endpoint",
            {"host": "example.test", "port": 443, "scheme": "https", "server": "Apache/2.4.58"},
            "test",
        )

        self.assertEqual(findings_from_event(event), [])

    def test_commandlet_dedupes_same_class_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="technology_indicators",
                metadata={"capabilities": ("db.write:finding.candidate", "framework.console.alert")},
            )
            events = [
                Event.new("http.endpoint", {"host": "example.test", "port": 80, "scheme": "http", "server": "Apache/2.4.49"}, "test"),
                Event.new("web.fingerprint", {"host": "example.test", "port": 80, "scheme": "http", "server": "Apache/2.4.49"}, "test"),
            ]

            list(technology_indicators.run(context, ["silent=true"], events))

            self.assertEqual(len(db.events_for_topic("finding.candidate")), 1)


if __name__ == "__main__":
    unittest.main()
