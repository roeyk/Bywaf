"""Direct tests for HTTP path finding classification helpers."""

from __future__ import annotations

import unittest
from typing import cast

from bywaf.event.schema_objects import HttpPathObserved
from bywaf.plugins.http.http_path_findings import finding_for_path, is_interesting_path, path_evidence


class HttpPathFindingHelperTests(unittest.TestCase):
    def test_is_interesting_path_rejects_error_statuses(self):
        self.assertFalse(
            is_interesting_path(
                "/.git/config",
                {
                    "status": 404,
                    "content_type": "text/plain",
                    "sample": "[core]\n\trepositoryformatversion = 0\n",
                },
            )
        )

    def test_is_interesting_path_requires_admin_evidence_for_admin_paths(self):
        self.assertTrue(
            is_interesting_path(
                "/admin/",
                {
                    "status": 200,
                    "title": "Admin Login",
                    "sample": "<form>Sign in</form>",
                },
            )
        )
        self.assertFalse(
            is_interesting_path(
                "/admin/",
                {
                    "status": 200,
                    "title": "Welcome",
                    "sample": "<p>Public page</p>",
                },
            )
        )

    def test_is_interesting_path_requires_artifact_markers_for_explicit_paths(self):
        self.assertTrue(
            is_interesting_path(
                "/package-lock.json",
                {
                    "status": 200,
                    "content_type": "application/json",
                    "sample": '{"lockfileVersion":3,"packages":{"":{"dependencies":{"vite":"5.0.0"}}}}',
                },
            )
        )
        self.assertFalse(
            is_interesting_path(
                "/package-lock.json",
                {
                    "status": 200,
                    "content_type": "text/html",
                    "sample": "<p>Dependency policy</p>",
                },
            )
        )

    def test_is_interesting_path_requires_cloud_app_config_markers(self):
        self.assertTrue(
            is_interesting_path(
                "/.aws/credentials",
                {
                    "status": 200,
                    "content_type": "text/plain",
                    "sample": "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secret",
                },
            )
        )
        self.assertFalse(
            is_interesting_path(
                "/.aws/credentials",
                {
                    "status": 200,
                    "content_type": "text/html",
                    "sample": "<p>AWS credential rotation policy</p>",
                },
            )
        )

    def test_finding_for_path_preserves_origin_scope_and_group_key(self):
        observed = HttpPathObserved(
            url="https://example.test/app/.git/config",
            host="example.test",
            port=443,
            path="/.git/config",
            status=200,
            content_type="text/plain",
            length=42,
            interesting=True,
        )

        finding = finding_for_path(observed)

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding["class"], "web.exposure.git_config")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertEqual(finding["group_key"], "web.exposure.git_config|web_origin:https://example.test|cwe:CWE-538")
        self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
        self.assertEqual(
            finding["affected"],
            [{"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/.git/config"}],
        )
        evidence = cast(str, finding["evidence"])
        self.assertIn("content-type=text/plain", evidence)

    def test_finding_for_cloud_app_config_uses_metadata_only_evidence(self):
        observed = HttpPathObserved(
            url="https://example.test/.aws/credentials",
            host="example.test",
            port=443,
            path="/.aws/credentials",
            status=200,
            content_type="text/plain",
            length=128,
            interesting=True,
        )

        finding = finding_for_path(observed)

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding["class"], "web.exposure.cloud_app_config")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertEqual(
            finding["group_key"],
            "web.exposure.cloud_app_config|web_origin:https://example.test|cwe:CWE-538",
        )
        self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
        evidence = cast(str, finding["evidence"])
        self.assertIn("https://example.test/.aws/credentials returned HTTP 200", evidence)
        self.assertNotIn("aws_secret_access_key", evidence)
        self.assertIn("rotate", cast(str, finding["recommendation"]))

    def test_finding_for_path_returns_none_when_observation_is_not_interesting(self):
        observed = HttpPathObserved(
            url="https://example.test/login",
            host="example.test",
            port=443,
            path="/login",
            status=200,
            interesting=False,
        )

        self.assertIsNone(finding_for_path(observed))

    def test_path_evidence_includes_present_response_metadata(self):
        observed = HttpPathObserved(
            url="https://example.test/.npmrc",
            host="example.test",
            port=443,
            path="/.npmrc",
            status=200,
            title="",
            content_type="text/plain",
            length=96,
            interesting=True,
        )

        self.assertEqual(
            path_evidence(observed),
            "https://example.test/.npmrc returned HTTP 200; content-type=text/plain; length=96",
        )


if __name__ == "__main__":
    unittest.main()
