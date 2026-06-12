# ruff: noqa: F403,F405
"""Resources/history/config tests split by responsibility.

Coverage focus: resources history config dispatch state regression behavior.
"""

from tests.resources_history_config.support import *  # noqa: F403,F405
class ResourcesHistoryDispatchStateTests(unittest.TestCase):
    """Groups regression coverage for resources/history/config tests split by responsibility."""
    def test_dispatch_plugin_help_does_not_exit_repl(self):
        """Protect dispatch plugin help does not exit repl behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = dispatch_repl_line(runner, "portscanner --help")
            self.assertIsNone(result)
            self.assertIn("usage: portscanner", output.getvalue())

    def test_dispatch_bad_plugin_argument_does_not_exit_repl(self):
        """Protect dispatch bad plugin argument does not exit repl behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            error = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                result = dispatch_repl_line(runner, "portscanner --bad-option")
            self.assertIsNone(result)
            self.assertIn("error: command failed with exit code 2", output.getvalue())
            self.assertIn("unrecognized arguments: --bad-option", error.getvalue())

    def test_dispatch_nmap_unavailable_does_not_exit_repl(self):
        """Protect dispatch nmap unavailable does not exit repl behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch(
                    "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                    side_effect=NmapUnavailableError("missing nmap"),
                ),
                contextlib.redirect_stdout(output),
            ):
                result = dispatch_repl_line(runner, "hostscanner 127.0.0.1")
            self.assertIsNone(result)
            self.assertIn("error: missing nmap", output.getvalue())

    def test_dispatch_nmap_scan_error_does_not_exit_repl(self):
        """Protect dispatch nmap scan error does not exit REPL behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch(
                    "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                    side_effect=NmapScanError("permission denied"),
                ),
                contextlib.redirect_stdout(output),
            ):
                result = dispatch_repl_line(runner, "hostscanner 127.0.0.1")
            self.assertIsNone(result)
            self.assertIn("error: permission denied", output.getvalue())

    def test_dispatch_unexpected_plugin_error_does_not_exit_repl(self):
        """Protect dispatch unexpected plugin error does not exit REPL behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch(
                    "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                    side_effect=Exception("unexpected"),
                ),
                contextlib.redirect_stdout(output),
            ):
                result = dispatch_repl_line(runner, "hostscanner 127.0.0.1")
            self.assertIsNone(result)
            self.assertIn("error: unexpected", output.getvalue())

    def test_dispatch_vars_lists_defaults(self):
        """Protect dispatch vars lists defaults behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set")
            self.assertIn("network/portscanner.port=", output.getvalue())

    def test_dispatch_vars_assignment_sets_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            dispatch_repl_line(runner, "set custom.value=abc")
            self.assertEqual(runner.registry.varstore.get("custom.value"), "abc")

    def test_dispatch_topics_and_show_use_database_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 127.0.0.1")
            topics = io.StringIO()
            shown = io.StringIO()
            with contextlib.redirect_stdout(topics):
                dispatch_repl_line(runner, "topics")
            with contextlib.redirect_stdout(shown):
                dispatch_repl_line(runner, "event host.found")
            self.assertIn("host.found", topics.getvalue())
            self.assertIn("127.0.0.1", shown.getvalue())

    def test_dispatch_show_job_prints_matching_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event job={job_id}")
            self.assertIn("commandlet=hostscanner", output.getvalue())
            self.assertIn("args=127.0.0.1", output.getvalue())

    def test_dispatch_prompt_sets_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            dispatch_repl_line(runner, "prompt %u@%h> ", state)
            self.assertEqual(state.prompt_pattern, "%u@%h> ")
            self.assertEqual(runner.db.events_for_topic("shell.prompt.updated")[0].payload["source"], "user")

    def test_set_prompt_pattern_records_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            set_prompt_pattern(runner, state, "new> ", source="test")
            event = runner.db.events_for_topic("shell.prompt.updated")[0]
            self.assertEqual(event.payload["old_prompt"], "$Y$M$D $h:$m:$s $Z%F> ")
            self.assertEqual(event.payload["new_prompt"], "new> ")
