"""Tests for app runtime arguments behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch runtime arguments regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

import bywaf
from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    make_runner,
)
from bywaf.plugins.network.nmap_backend import NmapPort



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app runtime arguments behavior."""
    def test_command_run_arguments_records_explicit_database_actions(self):
        """Protect command run arguments records explicit database actions behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "results")

            events = runner.db.events_matching(topic="command.run.arguments", limit=10)
            self.assertTrue(events)
            self.assertEqual(events[-1].payload["database_actions"], ["view"])
            self.assertEqual(events[-1].payload["plugin_version"], bywaf.__version__)
            self.assertEqual(events[-1].payload["bywaf_version"], bywaf.__version__)

    def test_mixed_commandlets_classify_effective_database_actions(self):
        """Protect mixed commandlets classify effective database actions behavior from regressions."""
        from bywaf.plugins.analysis.report import Report
        from bywaf.plugins.runtime.artifact import ArtifactCommand, SearchCommand
        from bywaf.plugins.runtime.bundle import BundleCommand
        from bywaf.plugins.runtime.job import Job
        from bywaf.plugins.runtime.key import Key
        from bywaf.plugins.runtime.note import Note
        from bywaf.plugins.runtime.pipeline import Pipeline
        from bywaf.runner.stages import effective_database_actions

        cases = [
            (Report(), ["status=all"], ("write",)),
            (Report(), ["status=all", "analyze=off"], ("view",)),
            (Report(), ["accept", "all"], ("write",)),
            (Report(), ["pipeline=1", "confirm", "1"], ("write",)),
            (ArtifactCommand(), ["list"], ("view",)),
            (ArtifactCommand(), ["attach", "file=x"], ("write",)),
            (SearchCommand(), ["name=x"], ("view",)),
            (BundleCommand(), ["verify", "name=x"], ("view",)),
            (BundleCommand(), ["seal", "name=x"], ("write",)),
            (Job(), [], ("view",)),
            (Job(), ["kill", "1"], ("write",)),
            (Key(), ["show", "name=x"], ("view",)),
            (Key(), ["generate", "name=x"], ("write",)),
            (Note(), ["step=1"], ("view",)),
            (Note(), ["add", "step=1", "text=x"], ("write",)),
            (Pipeline(), ["1"], ("view",)),
            (Pipeline(), ["attach", "1", "ports"], ("write",)),
        ]
        for plugin, args, expected in cases:
            with self.subTest(commandlet=plugin.spec.name, args=args):
                self.assertEqual(effective_database_actions(plugin, args), expected)

    def test_result_alias_shows_generic_inserted_events(self):
        """Protect result alias shows generic inserted events behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 192.0.2.10", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="pipeline",
                command_run_id="step",
                commandlet="hostscanner",
                values={},
            )
            runner.db.publish("host.found", {"host": "192.0.2.10"}, "hostscanner", pipeline_id="pipeline", command_run_id="step")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "result")

            text = output.getvalue()
            self.assertIn("Results: latest job=1", text)
            self.assertIn("Shared schemas: host.found", text)
            self.assertIn("Hosts discovered", text)
            self.assertIn("host.found", text)
            self.assertIn("192.0.2.10", text)

    def test_builtin_filters_expand_variables(self):
        """Protect builtin filters expand variables behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner")
            dispatch_repl_line(runner, "set A=192.0.2.20")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open host=$A")
            self.assertIn("192.0.2.20:443", output.getvalue())

    def test_builtin_expansion_preview_honors_display_mode(self):
        """Protect builtin expansion preview honors display mode behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner")
            dispatch_repl_line(runner, "set A=192.0.2.20")
            dispatch_repl_line(runner, "set display.expansion=changed")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open host=$A")
            self.assertIn("expanded: event port.open host=192.0.2.20", output.getvalue())

    def test_builtin_expansion_preview_redacts_secret_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32):
                dispatch_repl_line(runner, "set --secret TOKEN=supersecret", state)
            dispatch_repl_line(runner, "set display.expansion=changed", state)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open topic=$TOKEN", state)
            text = output.getvalue()
            self.assertIn("expanded: event port.open topic=[REDACTED#", text)
            self.assertNotIn("$__secret_", text)
            self.assertNotIn("supersecret", text)

    def test_commandlet_expansion_preview_honors_display_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            dispatch_repl_line(runner, "set TARGET=192.0.2.20")
            dispatch_repl_line(runner, "set display.expansion=changed")
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("192.0.2.20", 80, "tcp", "open", "http")],
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "network/portscanner host=$TARGET port=80")
            self.assertIn("expanded: network/portscanner --host 192.0.2.20 --port 80", output.getvalue())

    def test_repl_strips_inline_comments_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            dispatch_repl_line(runner, "set A=192.0.2.20 # operator note")
            self.assertEqual(runner.registry.varstore.get("A"), "192.0.2.20")


if __name__ == "__main__":
    unittest.main()
