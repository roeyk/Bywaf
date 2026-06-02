"""Tests for passive management exposure classification."""

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
    def test_redis_open_port_becomes_service_finding(self):
        event = Event.new("port.open", {"host": "192.0.2.10", "port": 6379, "protocol": "tcp"}, "test")

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])
        target = cast(dict[str, Any], finding["target"])

        self.assertEqual(finding["class"], "service.management.redis_exposed")
        self.assertEqual(finding["finding_scope"], "service")
        self.assertEqual(target["host"], "192.0.2.10")

    def test_grafana_web_fingerprint_becomes_web_origin_finding(self):
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
        self.assertEqual(finding["finding_scope"], "web_origin")
        self.assertEqual(affected[0]["url"], "https://grafana.example.test:3000/login")

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
