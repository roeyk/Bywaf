"""Regression tests for traceroute wrapper failure diagnostics.

Coverage focus: network traceroute wrapper regression behavior.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.network.traceroute import traceroute


class TracerouteWrapperTests(unittest.TestCase):
    """Groups regression coverage for traceroute wrapper failure diagnostics."""
    def test_nonzero_without_stdout_links_process_output_artifact(self):
        """Protect nonzero without stdout links process output artifact behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="traceroute",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": (
                        "artifact.write",
                        "db.read:process.run",
                        "db.write:host.found",
                        "db.write:tool.error",
                        "framework.console.alert",
                        "framework.console.output",
                        "framework.process.run",
                    ),
                },
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                del argv, cwd, env, timeout
                return subprocess.CompletedProcess([], 1, stdout="", stderr="name lookup failed")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(traceroute.run(context, ["binary=traceroute", "maxhops=1", "timeout=1", "silent=true", "example.test"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["message"], "name lookup failed")
            self.assertIn("artifact_id", error)

    def test_timeout_records_tool_error_without_route_hops(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="traceroute",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": (
                        "artifact.write",
                        "db.read:process.run",
                        "db.write:host.found",
                        "db.write:tool.error",
                        "framework.console.alert",
                        "framework.console.output",
                        "framework.process.run",
                    ),
                },
            )

            with patch("bywaf.plugin.process.run_process_argv", side_effect=subprocess.TimeoutExpired(["traceroute"], 1)):
                list(traceroute.run(context, ["binary=traceroute", "maxhops=1", "timeout=1", "silent=true", "example.test"], []))

            self.assertTrue(db.events_for_topic("tool.error"))
            self.assertEqual(db.events_for_topic("network.route.hop"), [])


if __name__ == "__main__":
    unittest.main()
