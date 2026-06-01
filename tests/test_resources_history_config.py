"""Tests for resources history config behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    format_history_entry_for_display,
    line_has_continuation,
    make_runner,
    record_command_history,
    remove_line_continuation,
    resolve_resource_path,
    run_script,
    save_history,
    set_prompt_pattern,
    load_history,
    script_commands,
    split_command_sequence,
    strip_inline_comment,
)
from bywaf.plugins.network.nmap_backend import NmapScanError, NmapUnavailableError
from bywaf.repl.shell import apply_startup_preferences
from bywaf.style import subject_style



class ResourcesHistoryConfigTests(unittest.TestCase):
    def test_dispatch_show_run_and_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
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
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("discovery/hostscanner.arguments", "-PE")
            runner.registry.varstore.set("global.proxy", "http://127.0.0.1:8080")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1")
            snapshot = runner.db.command_run_vars(events[0].command_run_id or "")
            self.assertEqual(snapshot["discovery/hostscanner.arguments"], "-PE")
            self.assertEqual(snapshot["global.proxy"], "http://127.0.0.1:8080")

    def test_background_job_uses_parent_var_snapshot(self):
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
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help set")
            self.assertIn("Usage:   set [--secret] [name[=value]]", output.getvalue())

    def test_dispatch_help_for_unknown_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help missing")
            self.assertIn("error: unknown command: missing", output.getvalue())

    def test_resolve_resource_path_uses_root_for_plain_plugin_names(self):
        self.assertEqual(resolve_resource_path("foo", Path(".bywaf/plugins")), Path(".bywaf/plugins/foo"))

    def test_resolve_resource_path_can_use_current_directory_root(self):
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

    def test_record_command_history_writes_script_friendly_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            session_history = []
            entry = record_command_history("ls bywaf", path, session_history)
            text = path.read_text()
            self.assertRegex(text, r"^ls bywaf  # \d{8} \d{2}:\d{2}:\d{2}( [A-Z]+)?\n$")
            self.assertEqual(script_commands(path)[0][1], "ls bywaf")
            self.assertEqual(session_history, [entry])

    def test_record_command_history_uses_configured_timestamp_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("plugins", path, timestamp_format="%Y/%m/%d")
            self.assertRegex(path.read_text(), r"^plugins  # \d{4}/\d{2}/\d{2}\n$")

    def test_record_command_history_accepts_redacted_stored_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("set password=supersecret", path, stored_command="set password=[REDACTED]")
            text = path.read_text()
            self.assertIn("set password=[REDACTED]", text)
            self.assertNotIn("supersecret", text)

    def test_record_command_history_redacts_common_secret_names_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("set password=supersecret", path)
            text = path.read_text()
            self.assertIn("set password=[REDACTED]", text)
            self.assertNotIn("supersecret", text)

    def test_format_history_entry_for_display_puts_timestamp_first(self):
        self.assertEqual(
            format_history_entry_for_display("plugins  # 2026-05-17 10:00:00 EDT"),
            "20260517 10:00:00 EDT  plugins",
        )
        self.assertEqual(
            format_history_entry_for_display("plugins  # 2026-05-17 EDT 10:00:00"),
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

    def test_load_script_records_auditable_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("set loaded.value=yes\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"script load file={script}")
            loaded = runner.db.events_for_topic("resource.script.loaded")[0]
            serial = loaded.payload["serial"]
            self.assertTrue(str(serial).startswith("script-"))
            self.assertIn(str(serial), runner.db.serials())
            commands = runner.db.events_for_serial(str(serial))
            self.assertEqual([event.topic for event in commands], ["resource.script.loaded", "resource.script.command"])
            self.assertEqual(commands[1].payload["command"], "set loaded.value=yes")

    def test_load_plugin_records_auditable_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "native = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force")
            self.assertIn("example", runner.registry.names())
            loaded = runner.db.events_for_topic("resource.plugin.loaded")[0]
            serial = loaded.payload["serial"]
            self.assertTrue(str(serial).startswith("plugin-"))
            self.assertEqual(loaded.payload["commandlet"], "example")
            self.assertEqual(runner.db.events_for_serial(str(serial)), [loaded])

    def test_pload_loads_plugin_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pload {plugin_dir} --force")
            self.assertIn("example", runner.registry.names())

    def test_plugin_load_use_selects_single_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use", state)
            self.assertEqual(state.active_context, "example")

    def test_plugin_load_prints_declared_variable_stubs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_external_plugin_with_vars(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/example --force", state)
            text = output.getvalue()
            self.assertIn("plugin variables:", text)
            self.assertIn("first=", text)
            self.assertIn("second=", text)
            self.assertIn("token=", text)
            self.assertIn("lab.proxy=", text)
            self.assertNotIn("hidden=", text)

    def test_plugin_load_use_lists_multiple_commandlets_without_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use", state)
            self.assertIsNone(state.active_context)
            self.assertIn("loaded plugin exposes multiple commandlets", output.getvalue())
            self.assertIn("use first", output.getvalue())
            self.assertIn("use second", output.getvalue())

    def test_plugin_load_use_specific_commandlet_selects_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use=second", state)
            self.assertEqual(state.active_context, "multi/second")

    def test_plugin_load_path_places_provider_in_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/tools --force", state)
                dispatch_repl_line(runner, "use lab/tools/example", state)
            self.assertEqual(state.active_context, "lab/tools/example")
            self.assertTrue(runner.registry.has_commandlet("lab/tools/example"))

    def test_use_provider_selects_manifest_default_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp), default_commandlet="second")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/multi --force", state)
                dispatch_repl_line(runner, "use lab/multi", state)
            self.assertEqual(state.active_context, "lab/multi/second")

    def test_use_provider_without_default_lists_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/multi --force", state)
                dispatch_repl_line(runner, "use lab/multi", state)
            self.assertIsNone(state.active_context)
            self.assertIn("lab/multi exposes multiple commandlets", output.getvalue())
            self.assertIn("first", output.getvalue())
            self.assertIn("second", output.getvalue())

    def test_use_accepts_provider_qualified_commandlet_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "use multi/second", state)
            self.assertEqual(state.active_context, "multi/second")

    def test_dispatch_accepts_provider_qualified_commandlet_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "example/example", state)
            events = runner.db.events_for_topic("example.done")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].source, "example")

    def test_external_plugin_enforces_declared_capabilities_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=False)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("capability policy denies undeclared capability", output.getvalue())
            missing = runner.db.events_for_topic("plugin.capability.missing")
            self.assertEqual(missing[0].payload["capability"], "framework.console.output")
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested"), [])

    def test_external_plugin_declared_capability_runs_under_default_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("hello from external", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("plugin.capability.missing"), [])

    def test_operator_can_downgrade_external_plugin_capability_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.capabilities.mode", "audit")
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=False)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("hello from external", output.getvalue())
            missing = runner.db.events_for_topic("plugin.capability.missing")
            self.assertEqual(missing[0].payload["capability"], "framework.console.output")

    def test_fully_qualified_commandlet_ignores_active_use_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            alpha = write_simple_external_plugin(Path(tmp), "alpha")
            beta = write_simple_external_plugin(Path(tmp), "beta")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={alpha} --force", state)
                dispatch_repl_line(runner, f"plugin load={beta} --force", state)
                dispatch_repl_line(runner, "use alpha", state)
                dispatch_repl_line(runner, "beta/beta", state)
            self.assertEqual(state.active_context, "alpha")
            self.assertEqual(len(runner.db.events_for_topic("alpha.done")), 0)
            self.assertEqual(len(runner.db.events_for_topic("beta.done")), 1)

    def test_script_fully_qualified_commandlet_ignores_active_use_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            alpha = write_simple_external_plugin(Path(tmp), "alpha")
            beta = write_simple_external_plugin(Path(tmp), "beta")
            script = Path(tmp, "script.bywaf")
            script.write_text("use alpha\nbeta/beta\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={alpha} --force", state)
                dispatch_repl_line(runner, f"plugin load={beta} --force", state)
                run_script(runner, script, state)
            self.assertEqual(state.active_context, "alpha")
            self.assertEqual(len(runner.db.events_for_topic("alpha.done")), 0)
            self.assertEqual(len(runner.db.events_for_topic("beta.done")), 1)

    def test_run_executes_active_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pload {plugin_dir} --force --use", state)
                dispatch_repl_line(runner, "run", state)
            events = runner.db.events_for_topic("example.done")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].payload["ok"], True)

    def test_run_requires_active_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "run", ShellState())
            self.assertIn("no active commandlet", output.getvalue())

    def test_load_plugin_refuses_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir}")
            self.assertIn("warning: refusing external plugin", output.getvalue())
            self.assertNotIn("example", runner.registry.names())

    def test_load_plugin_audits_manifest_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', capabilities=('network.connect',))\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "library_backed = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
                'capabilities = ["network.connect"]\n'
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force")
            loaded = runner.db.events_for_topic("resource.plugin.loaded")[0]
            self.assertEqual(loaded.payload["manifest"], str(plugin_dir / "bywaf.plugin.toml"))
            self.assertEqual(loaded.payload["traits"]["library_backed"], True)
            self.assertEqual(loaded.payload["capabilities"]["example"], ["network.connect"])
            self.assertRegex(str(loaded.payload["manifest_sha256"]), r"^[0-9a-f]{64}$")

    def test_regression_script_smoke_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(__file__).parent / "scripts" / "smoke_variables.bywaf"
            output = io.StringIO()
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, f"script load file={script}")
            discover.assert_called_once_with("127.0.0.1", "-sn")
            self.assertIn("script variable expansion", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("framework.variable.expanded")[0].payload["variables"], ["discovery/hostscanner.targets"])

    def test_save_and_load_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            config = Path(tmp, "vars.toml")
            dispatch_repl_line(runner, "set test.value=before")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config save file={config}")
            dispatch_repl_line(runner, "set test.value=after")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config load file={config}")
            self.assertEqual(runner.registry.varstore.get("test.value"), "before")
            self.assertIn("[variables]", config.read_text())

    def test_save_config_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            default_config = Path(tmp, "default.toml")
            dispatch_repl_line(runner, "set test.value=default")
            with (
                patch("bywaf.repl.command.resources.DEFAULT_CONFIG", default_config),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "config save file=")
            self.assertIn('"test.value" = "default"', default_config.read_text())

    def test_load_config_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            default_config = Path(tmp, "default.toml")
            default_config.write_text("[variables]\n\"test.value\" = \"default\"\n", encoding="utf-8")
            with (
                patch("bywaf.repl.command.resources.DEFAULT_CONFIG", default_config),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "config load file=")
            self.assertEqual(runner.registry.varstore.get("test.value"), "default")

    def test_load_legacy_json_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            config = Path(tmp, "vars.json")
            config.write_text('{"test.value": "legacy"}\n')
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config load file={config}")
            self.assertEqual(runner.registry.varstore.get("test.value"), "legacy")

    def test_config_theme_loads_named_preset(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, "config theme name=classic")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "cyan")
            self.assertEqual(runner.registry.varstore.get("display/style.string"), "bold yellow")

    def test_config_theme_loads_file_without_replacing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "theme.toml")
            theme.write_text(
                '[variables]\n"display/style.variable" = "bright-cyan"\n"display.expansion" = "changed"\n',
                encoding="utf-8",
            )
            runner.registry.varstore.set("test.value", "kept")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "bright-cyan")
            self.assertEqual(runner.registry.varstore.get("display.expansion"), "changed")
            self.assertEqual(runner.registry.varstore.get("test.value"), "kept")

    def test_config_theme_accepts_structured_foreground_background_styles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "theme.toml")
            theme.write_text(
                """
[variables."display/style.host"]
foreground = "cyan"
background = "transparent"
bold = true

[variables."display/style.finding.severity_class.emergency"]
foreground = "white"
background = "ansi:52"
bold = true
""",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertEqual(runner.registry.varstore.get("display/style.host"), "bold cyan")
            self.assertEqual(
                runner.registry.varstore.get("display/style.finding.severity_class.emergency"),
                "bold white bg:ansi:52",
            )

    def test_subject_style_accepts_direct_structured_variables(self):
        values = {
            "display/style.host.bold": "true",
            "display/style.host.foreground": "cyan",
            "display/style.host.background": "transparent",
            "display/style.finding.severity_class.emergency.foreground": "white",
            "display/style.finding.severity_class.emergency.background": "ansi:52",
        }

        self.assertEqual(subject_style(values.get, "host"), "bold cyan")
        self.assertEqual(subject_style(values.get, "finding.severity_class.emergency"), "white bg:ansi:52")

    def test_config_theme_rejects_non_display_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "bad-theme.toml")
            theme.write_text('[variables]\n"network/portscanner.host" = "127.0.0.1"\n', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertIn("theme variable must start with display.", output.getvalue())

    def test_pref_set_saves_and_applies_user_preference(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref set display.expansion=changed file={prefs}")
            self.assertEqual(runner.registry.varstore.get("display.expansion"), "changed")
            self.assertIn('"display.expansion" = "changed"', prefs.read_text())

    def test_pref_theme_saves_and_applies_named_theme(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref theme=classic file={prefs}")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "cyan")
            self.assertIn('"theme" = "classic"', prefs.read_text())

            other = make_runner(Path(tmp, "other.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(other, f"pref load file={prefs}")
            self.assertEqual(other.registry.varstore.get("display/style.variable"), "cyan")

    def test_pref_theme_lists_available_themes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pref theme")
            self.assertIn("themes: classic, default, mono", output.getvalue())

    def test_startup_preferences_create_default_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "home", ".bywaf", "preferences.toml")
            with patch("bywaf.repl.preferences.DEFAULT_PREFERENCES", prefs):
                apply_startup_preferences(runner, state)
            self.assertTrue(prefs.exists())
            self.assertEqual(prefs.read_text(encoding="utf-8"), "[preferences]\n")

    def test_pref_prompt_pattern_applies_to_shell_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref set prompt.pattern='test> ' file={prefs}", state)
            self.assertEqual(state.prompt_pattern, "test> ")
            self.assertIn('"prompt.pattern" = "test> "', prefs.read_text())

    def test_pref_prompt_short_form_persists_prompt_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref prompt '$u@$h> ' file={prefs}", state)
            self.assertEqual(state.prompt_pattern, "$u@$h> ")
            self.assertIn('"prompt.pattern" = "$u@$h> "', prefs.read_text())

    def test_pref_rejects_scanner_variables_but_allows_credential_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"pref set network/portscanner.host=127.0.0.1 file={prefs}")
                dispatch_repl_line(runner, f"pref set mail.smtp.password=secret file={prefs}")
            self.assertIn("not a preference key", output.getvalue())
            self.assertEqual(runner.registry.varstore.get("mail.smtp.password"), "secret")

    def test_save_and_load_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("custom.topic", {"ok": True}, "test")
            saved = Path(tmp, "saved.sqlite3")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"db export file={saved}")
            other = make_runner(Path(tmp, "other.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(other, f"db load file={saved} --force")
            self.assertEqual(other.db.path, saved)
            self.assertIn("custom.topic", other.db.topics())

    def test_save_history_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(session_history=["help  # 2026-05-21 12:00:00 EDT"])
            default_history = Path(tmp, "history.bywaf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.command.resources.DEFAULT_HISTORY", default_history),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "history save file=", state)
            self.assertIn("help", default_history.read_text())

    def test_load_history_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            default_history = Path(tmp, "history.bywaf")
            default_history.write_text("help  # 2026-05-21 12:00:00 EDT\n", encoding="utf-8")
            state = ShellState()
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.command.resources.DEFAULT_HISTORY", default_history),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "history load file=", state)
            self.assertEqual(state.session_history, ["help  # 2026-05-21 12:00:00 EDT"])

    def test_dispatch_plugin_help_does_not_exit_repl(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = dispatch_repl_line(runner, "portscanner --help")
            self.assertIsNone(result)
            self.assertIn("usage: portscanner", output.getvalue())

    def test_dispatch_bad_plugin_argument_does_not_exit_repl(self):
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



def write_simple_external_plugin(root: Path, name: str) -> Path:
    plugin_dir = root / name
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        f"class Example:\n"
        f"    spec = CommandSpec('{name}', '{name} plugin', emits=('{name}.done',))\n"
        "    def run(self, context, args, input_events):\n"
        "        del context, args, input_events\n"
        "        yield {'ok': True}\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        f'name = "{name}"\n'
        "capabilities = []\n"
    )
    return plugin_dir


def write_console_external_plugin(root: Path, *, declare_output: bool) -> Path:
    plugin_dir = root / "external_console"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        f"CAPABILITIES = {('framework.console.output',) if declare_output else ()!r}\n"
        "class Example:\n"
        "    spec = CommandSpec('external_console', 'external console plugin', capabilities=CAPABILITIES)\n"
        "    def run(self, context, args, input_events):\n"
        "        del args, input_events\n"
        "        context.output('hello from external')\n"
        "        return ()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    capabilities = '["framework.console.output"]' if declare_output else "[]"
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "external_console"\n'
        f"capabilities = {capabilities}\n"
    )
    return plugin_dir


def write_external_plugin_with_vars(root: Path) -> Path:
    plugin_dir = root / "vars"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "from bywaf.specs import OptionSpec\n"
        "class Example:\n"
        "    spec = CommandSpec(\n"
        "        'example',\n"
        "        'example plugin',\n"
        "        options=(OptionSpec('first', 'first'), OptionSpec('second', 'second'), OptionSpec('token', 'token', secret=True)),\n"
        "        provider_variables=('proxy',),\n"
        "    )\n"
        "    def run(self, context, args, input_events):\n"
        "        del context, args, input_events\n"
        "        return ()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "example"\n'
        'secret_options = ["token"]\n'
        'provider_variables = ["proxy"]\n'
        "capabilities = []\n"
    )
    (plugin_dir / "defaults.toml").write_text("[defaults]\nhidden = true\n")
    return plugin_dir


def write_multi_external_plugin(root: Path, *, default_commandlet: str | None = None) -> Path:
    plugin_dir = root / "multi"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "class First:\n"
        "    spec = CommandSpec('first', 'first plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        return ()\n"
        "class Second:\n"
        "    spec = CommandSpec('second', 'second plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        return ()\n"
        "def plugins():\n"
        "    return (First(), Second())\n"
    )
    plugin_table = "[plugin]\n" + (f'default_commandlet = "{default_commandlet}"\n\n' if default_commandlet else "\n")
    (plugin_dir / "bywaf.plugin.toml").write_text(
        plugin_table +
        "[[commandlets]]\n"
        'name = "first"\n'
        "capabilities = []\n\n"
        "[[commandlets]]\n"
        'name = "second"\n'
        "capabilities = []\n"
    )
    return plugin_dir


class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
