# ruff: noqa: F403,F405
"""Resources/history/config tests split by responsibility.

Coverage focus: resources history config runtime help scripts history regression behavior.
"""

from tests.resources_history_config.support import *  # noqa: F403,F405


class ResourcesHistoryRuntimeTests(unittest.TestCase):
    """Runtime help, script parsing, history, notes, and resource path tests.

    These scenarios intentionally go through public dispatch helpers where
    possible because they protect user-visible REPL behavior and formatting.
    """

    def test_dispatch_show_run_and_pipeline(self):
        """Protect dispatch show run and pipeline behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            # Seed a run with captured variables so event display can show both
            # scoped events and the command-run variable snapshot.
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"discovery/hostscanner.arguments": "-sn", "global.proxy": "http://127.0.0.1:8080"},
            )
            run_output = io.StringIO()
            pipe_output = io.StringIO()
            with contextlib.redirect_stdout(run_output):
                dispatch_repl_line(runner, "event step=r")
            with contextlib.redirect_stdout(pipe_output):
                dispatch_repl_line(runner, "event pipeline=p")
            self.assertIn("127.0.0.1", run_output.getvalue())
            self.assertIn("Variables:", run_output.getvalue())
            self.assertIn("discovery/hostscanner.arguments=-sn", run_output.getvalue())
            self.assertIn("global.proxy=http://127.0.0.1:8080", run_output.getvalue())
            self.assertIn("127.0.0.1", pipe_output.getvalue())

    def test_runner_snapshots_command_run_vars(self):
        """Protect runner snapshots command run vars behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("discovery/hostscanner.arguments", "-PE")
            runner.registry.varstore.set("global.proxy", "http://127.0.0.1:8080")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1")
            snapshot = runner.db.command_run_vars(events[0].command_run_id or "")
            # Command-run snapshots are the provenance layer that later report,
            # event, and step views use to explain how a scan was configured.
            self.assertEqual(snapshot["discovery/hostscanner.arguments"], "-PE")
            self.assertEqual(snapshot["global.proxy"], "http://127.0.0.1:8080")

    def test_background_job_uses_parent_var_snapshot(self):
        """Protect background job uses parent var snapshot behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("discovery/hostscanner.arguments", "-PE")
            with patch("bywaf.runner.core.mp.Process") as process_cls:
                process_cls.return_value.pid = 123
                event = runner.execute("hostscanner 127.0.0.1 &")[0]
            self.assertEqual(event.topic, "job.requested")
            process_cls.return_value.start.assert_called_once()
            with runner.db.connect() as conn:
                rows = list(conn.execute("SELECT name, value FROM command_run_vars WHERE commandlet = 'discovery/hostscanner'"))
            snapshot = {row["name"]: row["value"] for row in rows}
            self.assertEqual(snapshot["discovery/hostscanner.arguments"], "-PE")

    def test_dispatch_help_for_plugin(self):
        """Protect dispatch help for plugin behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help hostscanner")
            text = output.getvalue()
            self.assertIn("usage: hostscanner", text)
            self.assertIn("--arguments", text)
            self.assertIn("--limit", text)

    def test_help_plugin_matches_plugin_help_argument(self):
        """Protect help plugin matches plugin help argument behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            help_output = io.StringIO()
            argparse_output = io.StringIO()
            with contextlib.redirect_stdout(help_output):
                dispatch_repl_line(runner, "help http_headers")
            with contextlib.redirect_stdout(argparse_output):
                dispatch_repl_line(runner, "http_headers --help")
            self.assertEqual(help_output.getvalue(), argparse_output.getvalue())

    def test_dispatch_help_for_builtin(self):
        """Protect dispatch help for builtin behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help set")
            self.assertIn("Usage:   set [--secret] [name[=value]]", output.getvalue())

    def test_dispatch_help_for_unknown_command(self):
        """Protect dispatch help for unknown command behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help missing")
            self.assertIn("error: unknown command: missing", output.getvalue())

    def test_resolve_resource_path_uses_root_for_plain_plugin_names(self):
        """Protect resolve resource path uses root for plain plugin names behavior from regressions."""
        self.assertEqual(resolve_resource_path("foo", Path(".bywaf/plugins")), Path(".bywaf/plugins/foo"))

    def test_resolve_resource_path_can_use_current_directory_root(self):
        """Protect resolve resource path can use current directory root behavior from regressions."""
        self.assertEqual(resolve_resource_path("foo.bywaf", Path(".")), Path("foo.bywaf"))

    def test_resolve_resource_path_preserves_explicit_paths(self):
        self.assertEqual(resolve_resource_path("./foo", Path(".bywaf/plugins")), Path("foo"))
        self.assertEqual(resolve_resource_path("~/foo", Path(".bywaf/plugins")), Path("~/foo").expanduser())

    def test_resolve_resource_path_uses_default_for_empty_values(self):
        self.assertEqual(resolve_resource_path("", Path(".bywaf/db"), Path(".bywaf/bywaf.sqlite3")), Path(".bywaf/bywaf.sqlite3"))

    def test_script_commands_ignores_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "script.bywaf")
            path.write_text("# comment\n\nls  # timestamp\n  topics  \n")
            self.assertEqual(script_commands(path), [(3, "ls"), (4, "topics")])

    def test_script_commands_preserves_quoted_hashes(self):
        # Hashes inside quotes are user data; only unquoted hashes start
        # comments in script/history files.
        self.assertEqual(strip_inline_comment("set name='a # b' # later").strip(), "set name='a # b'")
        self.assertEqual(strip_inline_comment('set color="#dc2626" # later').strip(), 'set color="#dc2626"')

    def test_script_commands_treats_hash_as_comment_and_allows_escaped_hashes(self):
        self.assertEqual(strip_inline_comment("set color=#dc2626"), "set color=")
        self.assertEqual(strip_inline_comment(r"set color=\#dc2626"), "set color=#dc2626")

    def test_split_command_sequence_respects_quoted_separators(self):
        self.assertEqual(
            split_command_sequence("set a=1; set b='two; still two'; topics"),
            ["set a=1", "set b='two; still two'", "topics"],
        )
        self.assertEqual(
            split_command_sequence("job --all\npipeline --all\nevents last=30"),
            ["job --all", "pipeline --all", "events last=30"],
        )
        self.assertEqual(
            split_command_sequence("set note='first line\nsecond line'\nevents"),
            ["set note='first line\nsecond line'", "events"],
        )

    def test_line_continuation_helpers(self):
        self.assertTrue(line_has_continuation("hostscanner \\"))
        self.assertFalse(line_has_continuation(r"echo two\\"))
        self.assertEqual(remove_line_continuation("hostscanner \\"), "hostscanner ")

    def test_script_commands_joins_continuations_and_splits_semicolons(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "script.bywaf")
            path.write_text("set first=one; set second=two\nhostscanner \\\n  127.0.0.1\n")
            self.assertEqual(
                script_commands(path),
                [
                    (1, "set first=one"),
                    (1, "set second=two"),
                    (2, "hostscanner \n  127.0.0.1"),
                ],
            )

    def test_record_command_history_records_session_history_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            session_history = []
            entry = record_command_history("ls bywaf", path, session_history)
            # The REPL keeps session history in memory here; persistent history
            # files are deliberately not written by this helper.
            self.assertFalse(path.exists())
            self.assertRegex(entry or "", r"^ls bywaf  # \d{8} \d{2}:\d{2}:\d{2}( [A-Z]+)?$")
            self.assertEqual(session_history, [entry])

    def test_record_command_history_uses_configured_timestamp_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            entry = record_command_history("plugins", path, timestamp_format="%Y/%m/%d")
            self.assertFalse(path.exists())
            self.assertRegex(entry or "", r"^plugins  # \d{4}/\d{2}/\d{2}$")

    def test_record_command_history_accepts_safe_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            entry = record_command_history("set scope=lab", path)
            self.assertFalse(path.exists())
            self.assertIn("set scope=lab", entry or "")

    def test_redact_history_command_redacts_common_secret_names_by_default(self):
        redacted = redact_history_command("set password=supersecret")

        self.assertEqual(redacted, "set password=[REDACTED]")

    def test_format_history_entry_for_display_puts_timestamp_first(self):
        self.assertEqual(
            format_history_entry("plugins  # 2026-05-17 10:00:00 EDT"),
            "20260517 10:00:00 EDT  plugins",
        )
        self.assertEqual(
            format_history_entry("plugins  # 2026-05-17 EDT 10:00:00"),
            "20260517 10:00:00 EDT  plugins",
        )

    def test_dispatch_history_prints_session_history_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("old-command", history_path)
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(history_path=history_path, session_history=["plugins  # 2026-05-17 10:00:00 EDT"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history", state)
            self.assertIn("20260517 10:00:00 EDT  plugins", output.getvalue())
            self.assertNotIn("old-command", output.getvalue())

    def test_dispatch_history_colors_timestamp_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.history.color", "always")
            state = ShellState(session_history=["plugins  # 2026-05-17 10:00:00 EDT"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history", state)
            self.assertIn("\x1b[32m20260517 10:00:00 EDT\x1b[0m  plugins", output.getvalue())

    def test_dispatch_history_uses_semantic_comment_style_when_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.comment", "bold color245")
            state = ShellState(session_history=["plugins  # 2026-05-17 10:00:00 EDT"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history", state)
            self.assertIn("\x1b[1;38;5;245m20260517 10:00:00 EDT\x1b[0m  plugins", output.getvalue())

    def test_dispatch_history_filters_since_until(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(
                session_history=[
                    "plugins  # 2026-05-17 09:00:00 EDT",
                    "cmds  # 2026-05-17 10:00:00 EDT",
                    "set  # 2026-05-17 11:00:00 EDT",
                ],
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history since=202605171000 until=202605171059", state)
            self.assertNotIn("plugins", output.getvalue())
            self.assertIn("cmds", output.getvalue())
            self.assertNotIn("set", output.getvalue())

    def test_dispatch_history_accepts_explicit_time_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(session_history=["plugins  # 2026/05/17 10:00:00"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history since=time:20260517 until=time:20260517", state)
            self.assertIn("plugins", output.getvalue())

    def test_save_and_load_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "history.bywaf")
            state = ShellState(session_history=["plugins  # now"])
            with contextlib.redirect_stdout(io.StringIO()):
                save_history(state, path)
            loaded = ShellState()
            with contextlib.redirect_stdout(io.StringIO()):
                load_history(loaded, path)
            self.assertEqual(loaded.session_history, ["plugins  # now"])
            self.assertEqual(loaded.history_path, path)

    def test_dispatch_save_and_load_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                runner = make_runner(Path(tmp, "db.sqlite3"))
                state = ShellState(session_history=["cmds  # now"])
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "history save file=session.bywaf", state)
                state.session_history = []
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "history load file=session.bywaf", state)
                self.assertEqual(state.session_history, ["cmds  # now"])
            finally:
                os.chdir(cwd)

    def test_load_script_executes_commands_sequentially(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("# comment\nset test.value=abc\nset\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                run_script(runner, script)
            self.assertEqual(runner.registry.varstore.get("test.value"), "abc")
            self.assertIn("test.value=abc", output.getvalue())

    def test_load_script_executes_semicolon_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("set one.value=1; set two.value=2\n")
            with contextlib.redirect_stdout(io.StringIO()):
                run_script(runner, script)
            self.assertEqual(runner.registry.varstore.get("one.value"), "1")
            self.assertEqual(runner.registry.varstore.get("two.value"), "2")

    def test_dispatch_load_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("set loaded.value=yes\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"script load file={script}")
            self.assertEqual(runner.registry.varstore.get("loaded.value"), "yes")

    def test_script_load_prefers_existing_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script_dir = Path(tmp, "scripts")
            script_dir.mkdir()
            script = script_dir / "manual.bywaf"
            script.write_text("set loaded.relative=yes\n")
            old_cwd = Path.cwd()
            with (
                patch("bywaf.repl.command.resources.DEFAULT_SCRIPT_DIR", Path(tmp, ".bywaf/scripts")),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                try:
                    os.chdir(tmp)
                    dispatch_repl_line(runner, "script load file=scripts/manual.bywaf")
                finally:
                    os.chdir(old_cwd)
            self.assertEqual(runner.registry.varstore.get("loaded.relative"), "yes")
