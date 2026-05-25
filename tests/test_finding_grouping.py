"""Tests for finding class and report grouping helpers."""

import unittest

from bywaf.finding_grouping import finding_group_key, normalized_target_scope
from bywaf.finding_taxonomy import validate_finding_class
from bywaf.findings import candidate_payload


class FindingGroupingTests(unittest.TestCase):
    def test_validate_finding_class_accepts_dotted_lowercase_classes(self):
        self.assertEqual(validate_finding_class("web.header.missing_hsts"), "web.header.missing_hsts")

    def test_validate_finding_class_rejects_display_text(self):
        with self.assertRaises(ValueError):
            validate_finding_class("Missing HSTS")

    def test_same_cve_and_web_origin_group_despite_different_pages(self):
        first = {
            "class": "web.xss.reflected",
            "target_scope": {"kind": "web_origin", "value": "https://example.test"},
            "target": {"scheme": "https", "host": "example.test", "path": "/"},
            "identifiers": {"cve": ["CVE-2026-1234"]},
            "affected": [{"url": "https://example.test/"}],
        }
        second = {
            "class": "web.xss.reflected",
            "target_scope": {"kind": "web_origin", "value": "https://example.test"},
            "target": {"scheme": "https", "host": "example.test", "path": "/admin"},
            "identifiers": {"cve": ["CVE-2026-1234"]},
            "affected": [{"url": "https://example.test/admin"}],
        }

        self.assertEqual(finding_group_key(first), finding_group_key(second))

    def test_endpoint_scope_keeps_different_routes_separate(self):
        first = {
            "class": "web.xss.reflected",
            "finding_scope": "web_route",
            "target": {"scheme": "https", "host": "example.test", "path": "/"},
            "identifiers": {"cve": ["CVE-2026-1234"]},
        }
        second = {
            "class": "web.xss.reflected",
            "finding_scope": "web_route",
            "target": {"scheme": "https", "host": "example.test", "path": "/admin"},
            "identifiers": {"cve": ["CVE-2026-1234"]},
        }

        self.assertNotEqual(finding_group_key(first), finding_group_key(second))

    def test_candidate_payload_derives_target_scope_and_group_key(self):
        payload = candidate_payload(
            title="Missing HTTP Strict Transport Security",
            finding_class="web.header.missing_hsts",
            severity="medium",
            confidence="medium",
            finding_scope="web_origin",
            target={"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
            identifiers={"cwe": ["CWE-319"]},
            evidence="HSTS header was absent.",
            source={"tool": "test"},
        )

        self.assertEqual(payload["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertEqual(payload["group_key"], "web.header.missing_hsts|web_origin:https://example.test|cwe:CWE-319")

    def test_normalized_target_scope_supports_host_port(self):
        scope = normalized_target_scope(
            {
                "finding_scope": "host_port",
                "target": {"host": "192.0.2.10", "port": "2323", "protocol": "tcp"},
            }
        )

        self.assertEqual(scope, {"kind": "host_port", "value": "192.0.2.10:2323/tcp"})


if __name__ == "__main__":
    unittest.main()
