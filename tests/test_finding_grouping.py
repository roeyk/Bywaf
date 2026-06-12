"""Tests for finding class and report grouping helpers.

Coverage focus: finding grouping regression behavior.
"""

import unittest

from bywaf.finding.grouping import finding_group_key, normalized_target_scope
from bywaf.finding.taxonomy import validate_finding_class
from bywaf.finding import candidate_payload, confirmed_payload, subject_value


class FindingGroupingTests(unittest.TestCase):
    """Groups regression coverage for finding class and report grouping helpers."""
    def test_validate_finding_class_accepts_dotted_lowercase_classes(self):
        """Protect validate finding class accepts dotted lowercase classes behavior from regressions."""
        self.assertEqual(validate_finding_class("web.header.missing_hsts"), "web.header.missing_hsts")

    def test_validate_finding_class_rejects_display_text(self):
        """Protect validate finding class rejects display text behavior from regressions."""
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
            confidence_basis="configuration_indicator",
            finding_scope="web_origin",
            target={"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
            identifiers={"cwe": ["CWE-319"]},
            evidence="HSTS header was absent.",
            source={"tool": "test"},
        )

        self.assertEqual(payload["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertEqual(payload["confidence_basis"], "configuration_indicator")
        self.assertEqual(payload["group_key"], "web.header.missing_hsts|web_origin:https://example.test|cwe:CWE-319")
        self.assertEqual(payload["subjects"]["title"], "finding.title")
        self.assertEqual(payload["subjects"]["target.host"], "host")
        self.assertEqual(payload["subjects"]["target.port"], "port")
        self.assertEqual(payload["subjects"]["target.path"], "path")
        self.assertEqual(payload["subjects"]["severity"], "severity")
        self.assertEqual(payload["subjects"]["evidence"], "evidence")

    def test_candidate_payload_accepts_subject_overrides_and_typed_values(self):
        payload = candidate_payload(
            title="Weak login",
            finding_class="web.auth.weak_login",
            severity="high",
            target={"host": "example.test"},
            evidence=subject_value("explanation", "Nikto reported weak login wording."),
            affected=[{"login": subject_value("username", "admin"), "path": "/admin"}],
            subjects={"affected[].login": "username"},
        )

        self.assertEqual(payload["evidence"]["subject"], "explanation")
        self.assertEqual(payload["affected"][0]["login"]["subject"], "username")
        self.assertEqual(payload["subjects"]["evidence"], "explanation")
        self.assertEqual(payload["subjects"]["affected[].login"], "username")
        self.assertEqual(payload["subjects"]["affected[].path"], "path")

    def test_confirmed_payload_uses_candidate_shape_with_confirmed_status(self):
        payload = confirmed_payload(
            title="Exposed Git repository configuration",
            finding_class="web.exposure.git_config",
            severity="high",
            target={"host": "example.test", "path": "/.git/config"},
            confidence_basis="safe_probe",
            evidence="Git config content was returned.",
        )

        self.assertEqual(payload["status"], "confirmed")
        self.assertEqual(payload["confidence"], "high")
        self.assertEqual(payload["confidence_basis"], "safe_probe")
        self.assertEqual(payload["subjects"]["title"], "finding.title")

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
