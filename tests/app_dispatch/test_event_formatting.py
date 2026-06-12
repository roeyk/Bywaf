"""Tests for compact REPL event formatting.

Coverage focus: app dispatch event formatting regression behavior.
"""

import unittest

from bywaf.app import format_event
from bywaf.event import Event


class EventFormattingTests(unittest.TestCase):
    """Groups regression coverage for compact REPL event formatting."""
    def test_format_event_falls_back_to_topic_and_payload(self):
        event = Event.new("topic", {"x": 1}, "test")
        self.assertIn("topic", format_event(event))

    def test_format_event_shows_portscanner_summary_readably(self):
        event = Event.new(
            "plugin.progress.completed",
            {
                "commandlet": "portscanner",
                "phase": "port_scan",
                "status": "completed",
                "message": "port scan completed",
                "current": 1,
                "total": 1,
                "unit": "hosts",
                "percent": 100.0,
                "open_ports": 0,
            },
            "portscanner",
        )
        text = format_event(event)
        self.assertIn("portscanner port_scan completed", text)
        self.assertIn("1/1 hosts", text)
        self.assertIn("open_ports=0", text)
        self.assertNotIn("{", text)

    def test_format_event_shows_open_port_readably(self):
        event = Event.new(
            "port.open",
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"},
            "portscanner",
        )
        self.assertEqual(format_event(event), "None: port.open 192.0.2.10:443/tcp https")

    def test_format_event_shows_console_alert_readably(self):
        event = Event.new(
            "console.alert",
            {
                "job_id": 370,
                "level": "alert",
                "message": "discovered port 80/tcp on host 142.251.153.119",
                "request_event_id": 25296,
                "source": "portscanner",
            },
            "framework",
        )
        text = format_event(event)
        self.assertEqual(text, "None: portscanner alert: discovered port 80/tcp on host 142.251.153.119")
        self.assertNotIn("{", text)

    def test_format_event_shows_common_operator_events_without_dict_dump(self):
        cases = [
            (
                "host.found",
                {"host": "192.0.2.10", "status": "up", "scanner": "nmap"},
                "host.found 192.0.2.10 up nmap",
            ),
            (
                "name.resolved",
                {"name": "example.test", "host": "203.0.113.10"},
                "name.resolved example.test -> 203.0.113.10",
            ),
            (
                "name.resolved",
                {"name": "legacy.test", "addresses": ["203.0.113.10", "203.0.113.11"]},
                "name.resolved legacy.test -> 203.0.113.10, 203.0.113.11",
            ),
            (
                "console.output",
                {"source": "job", "text": "JOB  SERIAL\n---  ------\n1    abc"},
                "job output: JOB  SERIAL",
            ),
            (
                "framework.console.output.requested",
                {"source": "job", "text": "JOB  SERIAL\n---  ------\n1    abc"},
                "job output requested: JOB  SERIAL",
            ),
            (
                "framework.console.alert.requested",
                {"source": "portscanner", "level": "alert", "message": "discovered port 443/tcp"},
                "portscanner alert requested alert: discovered port 443/tcp",
            ),
            (
                "plugin.capability.used",
                {"commandlet": "portscanner", "capability": "network.connect", "declared": True},
                "portscanner capability network.connect declared",
            ),
            (
                "plugin.capability.missing",
                {"commandlet": "portscanner", "capability": "db.read:*", "declared": False},
                "portscanner capability db.read:* missing",
            ),
            (
                "framework.trigger.fired",
                {
                    "trigger_id": "runtime.watchdog.network-access-starts-watchdog",
                    "action_command": "watchdog --session-service",
                    "trigger_event_topic": "plugin.capability.used",
                },
                "trigger fired runtime.watchdog.network-access-starts-watchdog",
            ),
            (
                "framework.process.run.requested",
                {"source": "nikto", "argv": ["nikto", "-host", "http://127.0.0.1/"], "timeout": 300.0},
                "nikto process requested: nikto -host http://127.0.0.1/ timeout=300.0",
            ),
            (
                "system.error",
                {"tool": "nikto", "severity": "error", "message": "nikto executable not found"},
                "nikto error: nikto executable not found",
            ),
            (
                "runtime.name.assigned",
                {"target_type": "pipeline", "target_id": "pipeline-1", "name": "client scan"},
                "pipeline pipeline-1 named client scan",
            ),
            (
                "finding.candidate",
                {
                    "title": "Missing HTTP Strict Transport Security",
                    "class": "web.header.missing_hsts",
                    "severity": "medium",
                    "target": {"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
                },
                "finding.candidate Missing HTTP Strict Transport Security https://example.test:443 medium",
            ),
            (
                "http.headers",
                {"host": "example.test", "port": 443, "status": 200, "headers": {"Server": "example"}},
                "http.headers example.test:443 status=200 headers=Server",
            ),
            (
                "tls.certificate",
                {
                    "host": "example.test",
                    "port": 443,
                    "subject": "commonName=example.test",
                    "issuer": "commonName=CA",
                    "not_after": "Jan 01 00:00:00 2035 GMT",
                    "san": ["example.test", "www.example.test"],
                },
                "tls.certificate example.test:443 subject=commonName=example.test",
            ),
            (
                "tls.probe.error",
                {"host": "example.test", "port": 443, "error": "handshake failed"},
                "tls.probe.error example.test:443 error=handshake failed",
            ),
            (
                "job.failed",
                {
                    "job_id": 376,
                    "started_at": "2026-05-22T10:00:00+00:00",
                    "command": "hostscanner 127.0.0.1",
                    "error": "nmap unavailable",
                },
                "job 376 failed",
            ),
        ]
        for topic, payload, expected in cases:
            with self.subTest(topic=topic):
                text = format_event(Event.new(topic, payload, "framework"))
                self.assertIn(expected, text)
                self.assertNotIn("{", text)


if __name__ == "__main__":
    unittest.main()
