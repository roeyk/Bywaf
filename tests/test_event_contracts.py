"""Tests for shared event payload contracts.

Provides coverage for the lightweight shared-topic contract registry used by
plugin authors, views, and future validation hooks.

Used by:
- pytest and CI: catch drift in shared event topic expectations.
- maintainers: document event payload compatibility through examples."""

import unittest

from bywaf.event_contracts import EVENT_CONTRACTS, validate_event_payload


class EventContractTests(unittest.TestCase):
    def test_shared_contracts_define_required_fields(self):
        self.assertIn("host.found", EVENT_CONTRACTS)
        self.assertEqual(EVENT_CONTRACTS["host.found"].required_fields, ("host",))
        self.assertEqual(EVENT_CONTRACTS["port.open"].required_fields, ("host", "port", "protocol"))
        self.assertEqual(EVENT_CONTRACTS["http.endpoint"].required_fields, ("url", "host", "port", "scheme"))
        self.assertEqual(EVENT_CONTRACTS["smb.share.found"].required_fields, ("host", "share"))

    def test_valid_shared_payloads_pass(self):
        cases = [
            ("host.found", {"host": "192.0.2.10", "status": "up", "scanner": "nmap"}),
            ("port.open", {"host": "192.0.2.10", "port": 445, "protocol": "tcp", "service": "microsoft-ds"}),
            ("http.endpoint", {"url": "https://example.test/", "host": "example.test", "port": 443, "scheme": "https", "status": 200}),
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

    def test_plugin_private_topics_are_free_form(self):
        self.assertEqual(validate_event_payload("smb_enum.raw_share_acl", {"any": object()}), [])


if __name__ == "__main__":
    unittest.main()
