from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf import BywafSession


class ApiTests(unittest.TestCase):
    def test_session_runs_command_and_exposes_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                events = session.run("hostscanner -s 127.0.0.1")
            self.assertEqual(events[0].topic, "host.found")
            self.assertEqual(session.events(topic="host.found")[0].payload["host"], "127.0.0.1")
            self.assertIn("job.finished", session.topics())

    def test_session_starts_background_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            event = session.run_background("job list")
            self.assertEqual(event.topic, "job.requested")
            self.assertEqual(session.jobs()[0]["status"], "queued")

    def test_session_lists_plugins_and_commandlets(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            self.assertIn("runtime", session.plugins())
            self.assertIn("job", session.commandlets()["runtime"])

    def test_session_config_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = BywafSession.open(Path(tmp, "db.sqlite3"))
            session.set_var("http_probe.cookie-file", "/tmp/cookies.txt")
            config = Path(tmp, "config.json")
            session.save_config(config)
            session.set_var("http_probe.cookie-file", "changed")
            session.load_config(config)
            self.assertEqual(session.get_var("http_probe.cookie-file"), "/tmp/cookies.txt")

    def test_encrypted_session_requires_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "passphrase"):
                BywafSession.open(Path(tmp, "db.sqlite3"), encrypted=True)


if __name__ == "__main__":
    unittest.main()
