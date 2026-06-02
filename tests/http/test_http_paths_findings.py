"""Focused HTTP path finding promotion tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.http.http_paths import http_paths


class HttpPathFindingTests(unittest.TestCase):
    def test_admin_login_surface_becomes_low_severity_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.http_paths.probe_path",
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

    def test_plain_login_path_without_admin_signal_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="http_paths",
                metadata={"capabilities": http_paths.spec.capabilities},
            )
            with patch(
                "bywaf.plugins.http.http_paths.probe_path",
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


if __name__ == "__main__":
    unittest.main()
