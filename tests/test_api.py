"""Tests for api behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: api regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from bywaf import BywafSession


TERMINAL_JOB_STATUSES = {"finished", "failed", "cancelled", "killed", "stale"}


def wait_for_session_jobs(session: BywafSession, *, timeout: float = 5.0):
    """Test helper for wait for session jobs."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        session.db.mark_stale_jobs()
        jobs = session.jobs()
        if jobs and all(job["status"] in TERMINAL_JOB_STATUSES for job in jobs):
            session.checkpoint()
            time.sleep(0.05)
            return jobs
        time.sleep(0.05)
    raise AssertionError("background session jobs did not finish before timeout")


class ApiTests(unittest.TestCase):
    """Groups regression coverage for api behavior."""
    def test_session_runs_command_and_exposes_events(self):
        """Protect session runs command and exposes events behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                events = session.run("hostscanner -s 127.0.0.1")
            self.assertEqual(events[0].topic, "host.found")
            self.assertEqual(session.events(topic="host.found")[0].payload["host"], "127.0.0.1")
            self.assertIn("job.finished", session.topics())

    def test_session_starts_background_command(self):
        """Protect session starts background command behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            event = session.run_background("job")
            self.assertEqual(event.topic, "job.requested")
            self.assertIn(wait_for_session_jobs(session)[0]["status"], TERMINAL_JOB_STATUSES)

    def test_session_lists_plugins_and_commandlets(self):
        """Protect session lists plugins and commandlets behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            self.assertIn("runtime", session.plugins())
            self.assertIn("job", session.commandlets()["runtime"])

    def test_session_config_round_trip(self):
        """Protect session config round trip behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            session.set_var("http/http_probe.cookie-file", "/tmp/cookies.txt")
            config = Path(tmp, "config.toml")
            session.save_config(config)
            session.set_var("http/http_probe.cookie-file", "changed")
            session.load_config(config)
            self.assertEqual(session.get_var("http/http_probe.cookie-file"), "/tmp/cookies.txt")
            self.assertIn("[variables]", config.read_text())

    def test_encrypted_session_requires_passphrase(self):
        """Protect encrypted session requires passphrase behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "passphrase"):
                BywafSession.open(Path(tmp, "db.sqlite3"), encrypted=True)


if __name__ == "__main__":
    unittest.main()
