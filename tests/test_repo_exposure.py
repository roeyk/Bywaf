"""Tests for repository exposure checks.

Provides pytest coverage for bundled source-control metadata exposure plugins.

Used by:
- pytest and CI: detect regressions in HTTP repository exposure checks.
- maintainers: document expected event and finding payload behavior.

Coverage focus: repo exposure regression behavior.
"""

from __future__ import annotations

import contextlib
import io
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.repo_exposure import (
    DetectionStatus,
    GitExposeCheck,
    RepoExposure,
    base_result,
    candidate_from_detection,
    endpoint_from_target_text,
    git_config_url,
    git_targets,
    looks_like_git_config,
)


class RepoExposureTests(unittest.TestCase):
    """Groups regression coverage for repository exposure checks."""
    def test_git_config_url_uses_root_metadata_path(self):
        """Protect git config url uses root metadata path behavior from regressions."""
        self.assertEqual(git_config_url("https://example.test/app/index.html"), "https://example.test/.git/config")

    def test_looks_like_git_config_requires_core_and_repository_format(self):
        """Protect looks like git config requires core and repository format behavior from regressions."""
        self.assertTrue(looks_like_git_config("[core]\n\trepositoryformatversion = 0\n"))
        self.assertFalse(looks_like_git_config("[core]\n\tbare = false\n"))

    def test_explicit_targets_are_normalized(self):
        """Protect explicit targets are normalized behavior from regressions."""
        payload = endpoint_from_target_text("example.test:8443")
        self.assertEqual(payload["url"], "http://example.test:8443/")
        self.assertEqual(payload["host"], "example.test")
        self.assertEqual(payload["port"], 8443)

    def test_run_accepts_target_key_value_argument(self):
        context = CommandContext(db=None, source="git_expose_check", metadata={"command_run_id": "run-1"})
        result = base_result(
            {"url": "http://127.0.0.1:8088/", "host": "127.0.0.1", "port": 8088, "scheme": "http"},
            "http://127.0.0.1:8088/.git/config",
            DetectionStatus.SAFE,
            http_status=404,
        )
        with patch("bywaf.plugins.http.repo_exposure.command.probe_git_config", return_value=result) as probe:
            events = list(GitExposeCheck().run(context, ["target=http://127.0.0.1:8088"], []))

        self.assertEqual(probe.call_args.args[1]["url"], "http://127.0.0.1:8088")
        self.assertEqual(events[0]["checked_url"], "http://127.0.0.1:8088/.git/config")

    def test_pipeline_targets_use_http_endpoint_events(self):
        event = Event.new("http.endpoint", {"url": "https://example.test/", "host": "example.test", "port": 443}, "test")
        self.assertEqual(git_targets([], [event]), [event.payload])

    def test_candidate_payload_uses_normalized_finding_shape(self):
        result = base_result(
            {"url": "https://example.test/", "host": "example.test", "port": 443, "scheme": "https"},
            "https://example.test/.git/config",
            DetectionStatus.CANDIDATE,
            http_status=200,
            evidence="[core]\n\trepositoryformatversion = 0\n",
        )

        candidate = candidate_from_detection(result)

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate["status"], "potential")
        self.assertEqual(candidate["severity"], "high")
        self.assertEqual(candidate["confidence"], "high")
        self.assertEqual(candidate["confidence_basis"], "safe_probe")
        self.assertEqual(candidate["class"], "web.exposure.git_config")
        self.assertEqual(candidate["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertEqual(candidate["group_key"], "web.exposure.git_config|web_origin:https://example.test|cwe:CWE-538")
        self.assertEqual(candidate["identifiers"], {"cwe": ["CWE-538"]})
        self.assertEqual(candidate["target"]["path"], "/.git/config")
        self.assertEqual(candidate["affected"], [{"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"}])
        self.assertIn("http_status=200", candidate["evidence"])
        self.assertIn("sample=[core]", candidate["evidence"])

    def test_run_publishes_candidate_for_exposed_git_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                db=db,
                source="git_expose_check",
                metadata={"command_run_id": "run-1", "capabilities": GitExposeCheck().spec.capabilities},
            )
            event = Event.new("http.endpoint", {"url": "https://example.test/", "host": "example.test", "port": 443}, "test")
            result = base_result(
                event.payload,
                "https://example.test/.git/config",
                DetectionStatus.CANDIDATE,
                http_status=200,
                evidence="[core]\n\trepositoryformatversion = 0\n",
            )
            output = io.StringIO()
            with patch("bywaf.plugins.http.repo_exposure.command.probe_git_config", return_value=result):
                with contextlib.redirect_stdout(output):
                    events = list(GitExposeCheck().run(context, [], [event]))

            self.assertEqual(events[0]["status"], "candidate")
            self.assertEqual(db.events_for_topic("finding.candidate")[0].payload["title"], "Exposed Git repository configuration")
            self.assertTrue(db.events_for_topic("framework.console.alert.requested"))
            self.assertEqual(output.getvalue(), "")

    def test_family_commandlet_marks_payload_with_family_and_check(self):
        context = CommandContext(db=None, source="repo_exposure", metadata={"command_run_id": "run-1"})
        event = Event.new("http.endpoint", {"url": "https://example.test/", "host": "example.test", "port": 443}, "test")
        result = base_result(
            event.payload,
            "https://example.test/.git/config",
            DetectionStatus.SAFE,
            http_status=404,
        )
        with patch("bywaf.plugins.http.repo_exposure.command.probe_git_config", return_value=result):
            events = list(RepoExposure().run(context, [], [event]))

        self.assertEqual(events[0]["family"], "repo_exposure")
        self.assertEqual(events[0]["check"], "git_config")

    def test_silent_suppresses_exposure_alert(self):
        context = CommandContext(db=None, source="git_expose_check", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            context.alert("hidden", silent=True)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
