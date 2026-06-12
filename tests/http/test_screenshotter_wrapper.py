"""Regression tests for the screenshotter EyeWitness wrapper alias.

Coverage focus: http screenshotter wrapper regression behavior.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.screenshotter import Screenshotter


def make_context(tmp: str) -> tuple[CommandContext, EventStore]:
    """Build a screenshotter context with strict capabilities enabled."""
    db = EventStore(Path(tmp, "bywaf.sqlite3"))
    return (
        CommandContext(
            db=db,
            source="screenshotter",
            metadata={"command_run_id": "run-1", "capabilities": Screenshotter().spec.capabilities},
        ),
        db,
    )


class ScreenshotterWrapperTests(unittest.TestCase):
    """Groups regression coverage for the screenshotter EyeWitness wrapper alias."""
    def test_missing_binary_records_system_error_and_raises(self):
        """Protect missing binary records system error and raises behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(tmp)
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "http_probe")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=FileNotFoundError("eyewitness")):
                with self.assertRaisesRegex(ValueError, "EyeWitness executable not found"):
                    list(Screenshotter().run(context, ["binary=missing-eyewitness"], [event]))

            error = db.events_for_topic("system.error")[0].payload
            self.assertEqual(error["tool"], "eyewitness")
            self.assertEqual(error["message"], "EyeWitness executable not found")
            self.assertEqual(db.events_for_topic("web.screenshotted_host"), [])

    def test_nonzero_exit_links_process_output_without_screenshot_facts(self):
        """Protect nonzero exit links process output without screenshot facts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(tmp)
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "http_probe")

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                """Test helper for fake run."""
                del argv, cwd, env, timeout
                return subprocess.CompletedProcess([], 4, stdout="partial stdout", stderr="fatal stderr")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(Screenshotter().run(context, [f"output-dir={Path(tmp, 'eye')}"], [event]))

            errors = [event.payload for event in db.events_for_topic("tool.error")]
            exit_error = next(error for error in errors if error["message"] == "EyeWitness exited with status 4")
            self.assertIn("artifact_id", exit_error)
            self.assertEqual(exit_error["stderr"], "fatal stderr")
            self.assertEqual(db.events_for_topic("web.screenshotted_host"), [])

    def test_timeout_records_tool_error_without_screenshot_facts(self):
        """Protect timeout records tool error without screenshot facts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(tmp)
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "http_probe")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=subprocess.TimeoutExpired(["eyewitness"], 1)):
                list(Screenshotter().run(context, [f"output-dir={Path(tmp, 'eye')}"], [event]))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["message"], "EyeWitness run timed out")
            self.assertEqual(db.events_for_topic("eyewitness.screenshot"), [])
            self.assertEqual(db.events_for_topic("web.screenshotted_host"), [])

    def test_no_selected_endpoints_records_warning(self):
        """Protect no selected endpoints records warning behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(tmp)

            with patch("bywaf.plugin.process.run_process_argv") as run_process:
                events = list(Screenshotter().run(context, ["source=explicit"], []))

            self.assertEqual(events, [])
            run_process.assert_not_called()
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["severity"], "warning")
            self.assertEqual(error["message"], "no HTTP endpoints selected for EyeWitness")

    def test_successful_run_emits_screenshotter_sourced_artifacts(self):
        """Protect successful run emits screenshotter sourced artifacts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(tmp)
            output_dir = Path(tmp, "eye")
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "http_probe")

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                del cwd, env, timeout
                screenshot_dir = Path(argv[argv.index("-d") + 1]) / "screens"
                screenshot_dir.mkdir(parents=True)
                Path(screenshot_dir, "example.png").write_bytes(b"png")
                return SimpleNamespace(ok=True, returncode=0, stdout="", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(Screenshotter().run(context, [f"output-dir={output_dir}"], [event]))

            screenshot_event = db.events_for_topic("eyewitness.screenshot")[0]
            self.assertEqual(screenshot_event.source, "screenshotter")
            self.assertEqual(screenshot_event.payload["relative_path"], "screens/example.png")

    def test_value_carrying_output_dir_flag_is_rejected(self):
        """Protect value carrying output dir flag is rejected behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context, _db = make_context(tmp)
            with self.assertRaisesRegex(ValueError, "output-dir=path"):
                list(Screenshotter().run(context, [f"--output-dir={Path(tmp, 'eye')}"], []))


if __name__ == "__main__":
    unittest.main()
