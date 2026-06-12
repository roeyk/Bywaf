"""Tests for passive management exposure classification.

Coverage focus: network management exposure regression behavior.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.network.management_exposure import findings_from_event, management_exposure


class ManagementExposureTests(unittest.TestCase):
    """Groups regression coverage for passive management exposure classification."""
    def test_redis_open_port_becomes_service_finding(self):
        """Protect redis open port becomes service finding behavior from regressions."""
        event = Event.new("port.open", {"host": "192.0.2.10", "port": 6379, "protocol": "tcp"}, "test")

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])
        target = cast(dict[str, Any], finding["target"])

        self.assertEqual(finding["class"], "service.management.redis_exposed")
        self.assertEqual(finding["confidence_basis"], "port_indicator")
        self.assertEqual(finding["finding_scope"], "service")
        self.assertEqual(finding["target_scope"], {"kind": "service", "value": "192.0.2.10:6379/tcp"})
        self.assertEqual(finding["group_key"], "service.management.redis_exposed|service:192.0.2.10:6379/tcp|class")
        self.assertEqual(target["host"], "192.0.2.10")
        self.assertIn("192.0.2.10:6379/tcp matched redis", finding["evidence"])
        self.assertIn("source=port.open", finding["evidence"])
        self.assertIn("Bind Redis", finding["recommendation"])

    def test_grafana_web_fingerprint_becomes_web_origin_finding(self):
        """Protect grafana web fingerprint becomes web origin finding behavior from regressions."""
        event = Event.new(
            "web.fingerprint",
            {
                "url": "https://grafana.example.test:3000/login",
                "host": "grafana.example.test",
                "port": 3000,
                "scheme": "https",
                "title": "Grafana",
                "technologies": ["grafana"],
            },
            "test",
        )

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])
        affected = cast(list[dict[str, Any]], finding["affected"])

        self.assertEqual(finding["class"], "service.management.grafana_exposed")
        self.assertEqual(finding["confidence_basis"], "fingerprint_indicator")
        self.assertEqual(finding["finding_scope"], "web_origin")
        self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://grafana.example.test:3000"})
        self.assertEqual(
            finding["group_key"],
            "service.management.grafana_exposed|web_origin:https://grafana.example.test:3000|class",
        )
        self.assertEqual(affected[0]["url"], "https://grafana.example.test:3000/login")
        self.assertIn("https://grafana.example.test:3000/login matched grafana", finding["evidence"])
        self.assertIn("source=web.fingerprint", finding["evidence"])

    def test_grafana_port_without_web_evidence_is_not_promoted(self):
        """Protect grafana port without web evidence is not promoted behavior from regressions."""
        event = Event.new("port.open", {"host": "192.0.2.10", "port": 3000, "protocol": "tcp"}, "test")

        self.assertEqual(findings_from_event(event), [])

    def test_grafana_service_label_is_promoted_without_port_match(self):
        """Protect grafana service label is promoted without port match behavior from regressions."""
        event = Event.new(
            "service.detected",
            {"host": "192.0.2.10", "port": 8443, "protocol": "tcp", "service": "grafana"},
            "test",
        )

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])

        self.assertEqual(finding["class"], "service.management.grafana_exposed")
        self.assertEqual(finding["confidence_basis"], "service_indicator")
        self.assertIn("observed=grafana", finding["evidence"])

    def test_commandlet_dedupes_equivalent_service_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="management_exposure",
                metadata={"capabilities": ("db.write:finding.candidate", "framework.console.alert")},
            )
            events = [
                Event.new("port.open", {"host": "192.0.2.10", "port": 6379, "protocol": "tcp"}, "test"),
                Event.new("service.detected", {"host": "192.0.2.10", "port": 6379, "protocol": "tcp", "service": "redis"}, "test"),
            ]

            list(management_exposure.run(context, ["silent=true"], events))

            findings = db.events_for_topic("finding.candidate")
            self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
