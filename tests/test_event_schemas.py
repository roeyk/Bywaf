"""Tests for shared event payload schemas.

Provides coverage for the lightweight shared-topic schema registry used by
plugin authors, views, and future validation hooks.

Used by:
- pytest and CI: catch drift in shared event topic expectations.
- maintainers: document event payload compatibility through examples."""

import unittest

from dataclasses import dataclass

from bywaf.event_schema_objects import ArtifactAttached, HostFound, HttpEndpoint, NameResolved, NetworkRouteHop, OpenPort, ScreenshottedHost, SmbShareFound, TcpBanner
from bywaf.event_schemas import EVENT_SCHEMAS, EventSchemaObject, schema_object, validate_event_payload
from bywaf.events import Event


@dataclass(frozen=True)
class PluginPrivateSession(EventSchemaObject):
    __topic__ = "smb.session.observed"

    host: str
    username: str
    domain: str = ""


class EventSchemaTests(unittest.TestCase):
    def test_shared_schemas_define_required_fields(self):
        self.assertIn("host.found", EVENT_SCHEMAS)
        self.assertEqual(EVENT_SCHEMAS["host.found"].required_fields, ("host",))
        self.assertEqual(EVENT_SCHEMAS["port.open"].required_fields, ("host", "port", "protocol"))
        self.assertEqual(EVENT_SCHEMAS["http.endpoint"].required_fields, ("url", "host", "port", "scheme"))
        self.assertEqual(EVENT_SCHEMAS["web.screenshotted_host"].required_fields, ("host", "urls", "screenshots"))
        self.assertEqual(EVENT_SCHEMAS["tcp.banner"].required_fields, ("host", "port", "protocol"))
        self.assertEqual(EVENT_SCHEMAS["network.route.hop"].required_fields, ("target", "hop"))
        self.assertEqual(EVENT_SCHEMAS["smb.share.found"].required_fields, ("host", "share"))

    def test_valid_shared_payloads_pass(self):
        cases = [
            ("host.found", {"host": "192.0.2.10", "status": "up", "scanner": "nmap"}),
            ("port.open", {"host": "192.0.2.10", "port": 445, "protocol": "tcp", "service": "microsoft-ds"}),
            ("http.endpoint", {"url": "https://example.test/", "host": "example.test", "port": 443, "scheme": "https", "status": 200}),
            ("web.screenshotted_host", {"host": "example.test", "urls": ["https://example.test/"], "screenshots": [{"artifact_id": "artifact-1"}]}),
            ("tcp.banner", {"host": "192.0.2.10", "port": 22, "protocol": "tcp", "banner": "SSH-2.0-OpenSSH"}),
            ("network.route.hop", {"target": "example.test", "hop": 1, "host": "192.0.2.1", "rtt_ms": 1.5, "status": "responded"}),
            ("smb.share.found", {"host": "dc01.example.test", "share": "SYSVOL", "access": "read", "authenticated": True}),
            ("finding.candidate", {"title": "Example finding", "class": "example.finding"}),
            ("artifact.attached", {"artifact_id": "artifact-1", "name": "scan.json", "content_type": "application/json", "sha256": "a" * 64, "size": 10}),
        ]
        for topic, payload in cases:
            with self.subTest(topic=topic):
                self.assertEqual(validate_event_payload(topic, payload), [])

    def test_invalid_shared_payloads_report_field_errors(self):
        self.assertEqual(
            validate_event_payload("port.open", {"host": "192.0.2.10", "port": "445"}),
            ["port.open.port must be int", "port.open.protocol is required"],
        )
        self.assertEqual(
            validate_event_payload("http.endpoint", {"url": "ftp://example.test/", "host": "example.test", "port": 21, "scheme": "ftp"}),
            ["http.endpoint.scheme must be one of: http, https"],
        )
        self.assertEqual(
            validate_event_payload("smb.share.found", {"host": "dc01", "share": "Backups", "access": "admin"}),
            ["smb.share.found.access must be one of: unknown, none, read, write, read_write"],
        )
        self.assertEqual(
            validate_event_payload("tcp.banner", {"host": "192.0.2.10", "port": 22, "protocol": "udp"}),
            ["tcp.banner.protocol must be one of: tcp"],
        )
        self.assertEqual(
            validate_event_payload("network.route.hop", {"target": "example.test", "hop": "1"}),
            ["network.route.hop.hop must be int"],
        )

    def test_plugin_private_topics_are_free_form(self):
        self.assertEqual(validate_event_payload("smb_enum.raw_share_acl", {"any": object()}), [])

    def test_plugin_private_schema_objects_round_trip_without_framework_registry(self):
        session = PluginPrivateSession("dc01.example.test", "alice", "EXAMPLE")
        payload = session.to_payload()
        event = Event.new(PluginPrivateSession.__topic__, payload, "smb_enum")

        self.assertEqual(
            payload,
            {"host": "dc01.example.test", "username": "alice", "domain": "EXAMPLE"},
        )
        self.assertEqual(PluginPrivateSession.from_event(event), session)

    def test_schema_object_deserializes_event_into_plugin_object(self):
        event = Event.new(
            "port.open",
            {
                "host": "192.0.2.10",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "reason": "syn-ack",
            },
            "test",
        )

        port = schema_object(event, "port.open", OpenPort)

        self.assertEqual(
            port,
            OpenPort("192.0.2.10", 445, "tcp", service="microsoft-ds", reason="syn-ack"),
        )

    def test_schema_object_rejects_invalid_event_payload(self):
        event = Event.new("port.open", {"host": "192.0.2.10", "port": "445"}, "test")

        with self.assertRaisesRegex(ValueError, "port.open.port must be int"):
            schema_object(event, "port.open", OpenPort)

    def test_schema_object_base_deserializes_and_serializes_payloads(self):
        event = Event.new(
            "port.open",
            {
                "host": "192.0.2.10",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "scanner": "nmap",
            },
            "test",
        )

        port = OpenPort.from_event(event)

        self.assertEqual(port, OpenPort("192.0.2.10", 445, "tcp", service="microsoft-ds", scanner="nmap"))
        self.assertEqual(
            port.to_payload(),
            {
                "host": "192.0.2.10",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "scanner": "nmap",
            },
        )

    def test_route_hop_schema_object_round_trips(self):
        hop = NetworkRouteHop("example.test", 2, host="router", ip="192.0.2.1", rtt_ms=1.25, status="responded")
        event = Event.new("network.route.hop", hop.to_payload(), "traceroute")

        self.assertEqual(NetworkRouteHop.from_event(event), hop)

    def test_schema_object_base_rejects_invalid_serialized_payloads(self):
        port = OpenPort("192.0.2.10", 445, "icmp")

        with self.assertRaisesRegex(ValueError, "port.open.protocol must be one of"):
            port.to_payload()

    def test_framework_schema_objects_round_trip_common_shared_payloads(self):
        cases = [
            (HostFound("192.0.2.10", status="up", scanner="nmap"), "host.found"),
            (NameResolved("example.test", "192.0.2.10", resolver="system"), "name.resolved"),
            (HttpEndpoint("https://example.test/", "example.test", 443, "https", status=200), "http.endpoint"),
            (ScreenshottedHost("example.test", ["https://example.test/"], [{"artifact_id": "artifact-1"}]), "web.screenshotted_host"),
            (TcpBanner("192.0.2.10", 22, banner="SSH-2.0-OpenSSH"), "tcp.banner"),
            (SmbShareFound("dc01.example.test", "SYSVOL", access="read", authenticated=True), "smb.share.found"),
            (
                ArtifactAttached("artifact-1", "scan.json", "application/json", "a" * 64, 10),
                "artifact.attached",
            ),
        ]

        for obj, topic in cases:
            with self.subTest(topic=topic):
                payload = obj.to_payload()
                self.assertEqual(validate_event_payload(topic, payload), [])
                self.assertEqual(obj.__class__.from_event(Event.new(topic, payload, "test")), obj)


if __name__ == "__main__":
    unittest.main()
