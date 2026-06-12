"""Focused HTTP path finding promotion tests.

Coverage focus: http http paths findings regression behavior.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.http.paths import http_paths


class HttpPathFindingTests(unittest.TestCase):
    """Groups regression coverage for focused HTTP path finding promotion tests."""
    def test_admin_login_surface_becomes_low_severity_candidate(self):
        """Protect admin login surface becomes low severity candidate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 80,
                    "title": "Admin Login",
                    "sample": "<form>Sign in to administrator console</form>",
                },
            ):
                list(http_paths.run(context, ["paths=/admin/", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.admin_interface.exposed")
            self.assertEqual(finding["severity"], "low")
            self.assertEqual(finding["target"]["path"], "/admin/")
            self.assertIn("content-type=text/html", finding["evidence"])

    def test_git_config_path_uses_repo_exposure_finding_class_and_origin_scope(self):
        """Protect git config path uses repo exposure finding class and origin scope behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/plain",
                    "length": 42,
                    "sample": "[core]\n\trepositoryformatversion = 0\n",
                },
            ):
                list(http_paths.run(context, ["paths=/.git/config", "https://example.test/app"], []))

            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertEqual(finding["class"], "web.exposure.git_config")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["group_key"], "web.exposure.git_config|web_origin:https://example.test|cwe:CWE-538")
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertEqual(finding["affected"], [{"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"}])
            self.assertIn("content-type=text/plain", finding["evidence"])

    def test_plain_login_path_without_admin_signal_is_not_a_finding(self):
        """Protect plain login path without admin signal is not a finding behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 80,
                    "title": "Welcome",
                    "sample": "<p>Public landing page</p>",
                },
            ):
                list(http_paths.run(context, ["paths=/login", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload

            self.assertFalse(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_backup_archive_path_with_archive_content_type_becomes_candidate(self):
        """Protect backup archive path with archive content type becomes candidate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "application/zip",
                    "length": 2048,
                    "sample": "PK",
                },
            ):
                list(http_paths.run(context, ["paths=/backup.zip", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.backup.archive_exposed")
            self.assertEqual(finding["severity"], "medium")
            self.assertIn("length=2048", finding["evidence"])

    def test_database_dump_path_with_sql_markers_becomes_candidate(self):
        """Protect database dump path with sql markers becomes candidate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/plain",
                    "length": 120,
                    "sample": "-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);",
                },
            ):
                list(http_paths.run(context, ["paths=/database.sql", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.backup.database_dump_exposed")
            self.assertEqual(finding["severity"], "high")

    def test_backup_named_html_page_is_not_a_finding_without_artifact_evidence(self):
        """Protect backup named HTML page is not a finding without artifact evidence behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 120,
                    "title": "Backup instructions",
                    "sample": "<p>Backup policy and restore instructions</p>",
                },
            ):
                list(http_paths.run(context, ["paths=/backup.zip", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload

            self.assertFalse(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_source_map_path_with_map_markers_becomes_candidate(self):
        """Protect source map path with map markers becomes candidate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "application/json",
                    "length": 160,
                    "sample": '{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}',
                },
            ):
                list(http_paths.run(context, ["paths=/static/app.js.map", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.exposure.source_map")
            self.assertEqual(finding["severity"], "medium")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertIn("source-map access", finding["recommendation"])

    def test_source_map_named_html_page_is_not_a_finding_without_map_markers(self):
        """Protect source map named HTML page is not a finding without map markers behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 80,
                    "title": "Map",
                    "sample": "<p>Public map page</p>",
                },
            ):
                list(http_paths.run(context, ["paths=/static/app.js.map", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload

            self.assertFalse(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_legacy_vcs_metadata_path_becomes_origin_scoped_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/plain",
                    "length": 64,
                    "sample": "[paths]\ndefault = https://hg.example.test/project\n",
                },
            ):
                list(http_paths.run(context, ["paths=/.hg/hgrc", "https://example.test/app"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.exposure.source_control_metadata")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(
                finding["group_key"],
                "web.exposure.source_control_metadata|web_origin:https://example.test|cwe:CWE-538",
            )
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})

    def test_dependency_lockfile_path_with_markers_becomes_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "application/json",
                    "length": 180,
                    "sample": '{"lockfileVersion":3,"packages":{"":{"dependencies":{"vite":"5.0.0"}}}}',
                },
            ):
                list(http_paths.run(context, ["paths=/package-lock.json", "https://example.test/app"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.exposure.dependency_metadata")
            self.assertEqual(finding["severity"], "medium")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertEqual(
                finding["group_key"],
                "web.exposure.dependency_metadata|web_origin:https://example.test|cwe:CWE-538",
            )
            self.assertIn("dependency manifests", finding["recommendation"])

    def test_dependency_lockfile_named_html_page_is_not_a_finding_without_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 80,
                    "title": "Package lock",
                    "sample": "<p>Dependency policy page</p>",
                },
            ):
                list(http_paths.run(context, ["paths=/package-lock.json", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload

            self.assertFalse(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_sensitive_config_path_with_secret_markers_becomes_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/plain",
                    "length": 96,
                    "sample": "//registry.npmjs.org/:_authToken=npm_secret_token",
                },
            ):
                list(http_paths.run(context, ["paths=/.npmrc", "https://example.test/app"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.exposure.sensitive_config")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertEqual(
                finding["group_key"],
                "web.exposure.sensitive_config|web_origin:https://example.test|cwe:CWE-538",
            )
            self.assertIn("rotate", finding["recommendation"])

    def test_sensitive_config_named_html_page_is_not_a_finding_without_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/html",
                    "length": 80,
                    "title": "Config",
                    "sample": "<p>Configuration help page</p>",
                },
            ):
                list(http_paths.run(context, ["paths=/wp-config.php", "https://example.test"], []))

            path = db.events_for_topic("http.path")[0].payload

            self.assertFalse(path["interesting"])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_cloud_app_config_path_with_markers_becomes_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.paths.probe_path",
                return_value={
                    "status": 200,
                    "content_type": "text/plain",
                    "length": 128,
                    "sample": "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secret",
                },
            ):
                list(http_paths.run(context, ["paths=/.aws/credentials", "https://example.test/app"], []))

            path = db.events_for_topic("http.path")[0].payload
            finding = db.events_for_topic("finding.candidate")[0].payload

            self.assertTrue(path["interesting"])
            self.assertEqual(finding["class"], "web.exposure.cloud_app_config")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertEqual(
                finding["group_key"],
                "web.exposure.cloud_app_config|web_origin:https://example.test|cwe:CWE-538",
            )
            self.assertNotIn("aws_secret_access_key", finding["evidence"])


if __name__ == "__main__":
    unittest.main()
