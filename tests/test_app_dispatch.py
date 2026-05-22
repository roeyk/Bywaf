"""Tests for app dispatch behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    build_parser,
    dispatch_repl_line,
    extract_startup_project,
    format_event,
    main,
    make_runner,
    command_from_remainder,
    parse_load_spec,
    process_framework_requests,
    read_logical_input,
    repl,
    shutdown_runner,
    confirm_repl_exit,
)
from bywaf.cli_trust import plugin_trust_policy_from_args
from bywaf.db import EventStore
from bywaf.events import Event
from bywaf.specs import TriggerSpec
from bywaf.triggers import start_default_services
class AppDispatchTests(unittest.TestCase):
    def test_build_parser_accepts_run(self):
        parser = build_parser()
        args = parser.parse_args(["run", "hostscanner", "127.0.0.1"])
        self.assertEqual(args.subcommand, "run")
        self.assertEqual(args.command, ["hostscanner", "127.0.0.1"])

    def test_build_parser_accepts_cmds_page(self):
        parser = build_parser()
        args = parser.parse_args(["cmds", "--page"])
        self.assertEqual(args.subcommand, "cmds")
        self.assertTrue(args.page)
        self.assertEqual(args.database, ".bywaf/bywaf.sqlite3")

    def test_build_parser_accepts_builtin_commands(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["plugins"]).subcommand, "plugins")
        self.assertEqual(parser.parse_args(["cmds"]).subcommand, "cmds")
        self.assertEqual(parser.parse_args(["triggers"]).subcommand, "triggers")
        self.assertEqual(parser.parse_args(["history"]).subcommand, "history")
        self.assertEqual(parser.parse_args(["pipelines"]).subcommand, "pipelines")

    def test_build_parser_prefers_encrypt_flag(self):
        parser = build_parser()
        self.assertTrue(parser.parse_args(["--encrypt"]).encrypt)
        self.assertTrue(parser.parse_args(["--encrypted"]).encrypted)

    def test_build_parser_accepts_force_plugins(self):
        parser = build_parser()
        self.assertTrue(parser.parse_args(["--force-plugins"]).force_plugins)
        self.assertTrue(parser.parse_args(["--allow-untrusted-plugins"]).allow_untrusted_plugins)

    def test_build_parser_accepts_plugin_trust_bypasses(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "--allow-unsigned-plugins",
                "--allow-unsigned-plugin-manifests",
                "--allow-missing-plugin-keys",
                "--allow-mismatched-plugin-keys",
            ]
        )
        self.assertTrue(args.allow_unsigned_plugins)
        self.assertTrue(args.allow_unsigned_plugin_manifests)
        self.assertTrue(args.allow_missing_plugin_keys)
        self.assertTrue(args.allow_mismatched_plugin_keys)

    def test_plugin_trust_policy_tracks_unsigned_manifest_bypass(self):
        parser = build_parser()
        args = parser.parse_args(["--allow-unsigned-plugin-manifests"])

        policy = plugin_trust_policy_from_args(args)

        self.assertFalse(policy.allow_unsigned_plugins)
        self.assertTrue(policy.allow_unsigned_plugin_manifests)

    def test_build_parser_accepts_plugin_catalog_trust_inputs(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "--plugin-catalog",
                "catalog.json",
                "--plugin-catalog-key",
                "catalog.pub",
                "--plugin-manifest-key",
                "manifest.pub",
            ]
        )
        self.assertEqual(args.plugin_catalog, "catalog.json")
        self.assertEqual(args.plugin_catalog_key, "catalog.pub")
        self.assertEqual(args.plugin_manifest_key, "manifest.pub")

    def test_build_parser_rejects_direct_os_commandlets(self):
        parser = build_parser()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["ls"])

    def test_command_from_remainder_quotes_tokens(self):
        self.assertEqual(command_from_remainder(["cat", "file name.txt"]), "cat 'file name.txt'")

    def test_parse_load_spec_accepts_force_before_resource(self):
        forced, resource = parse_load_spec("--force plugin=example")
        self.assertTrue(forced)
        self.assertEqual(resource, "plugin=example")

    def test_command_from_remainder_preserves_single_quoted_pipeline(self):
        self.assertEqual(
            command_from_remainder(["ls bywaf/plugins/os | cat README.md"]),
            "ls bywaf/plugins/os | cat README.md",
        )

    def test_format_event(self):
        event = Event.new("topic", {"x": 1}, "test")
        self.assertIn("topic", format_event(event))

    def test_format_event_shows_portscanner_summary_readably(self):
        event = Event.new(
            "plugin.progress.completed",
            {
                "commandlet": "portscanner",
                "phase": "port_scan",
                "status": "completed",
                "message": "port scan completed",
                "current": 1,
                "total": 1,
                "unit": "hosts",
                "percent": 100.0,
                "open_ports": 0,
            },
            "portscanner",
        )
        text = format_event(event)
        self.assertIn("portscanner port_scan completed", text)
        self.assertIn("1/1 hosts", text)
        self.assertIn("open_ports=0", text)
        self.assertNotIn("{", text)

    def test_format_event_shows_open_port_readably(self):
        event = Event.new(
            "port.open",
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"},
            "portscanner",
        )
        self.assertEqual(format_event(event), "None: port.open 192.0.2.10:443/tcp https")

    def test_format_event_shows_console_alert_readably(self):
        event = Event.new(
            "console.alert",
            {
                "job_id": 370,
                "level": "alert",
                "message": "discovered port 80/tcp on host 142.251.153.119",
                "request_event_id": 25296,
                "source": "portscanner",
            },
            "framework",
        )
        text = format_event(event)
        self.assertEqual(text, "None: portscanner alert: discovered port 80/tcp on host 142.251.153.119")
        self.assertNotIn("{", text)

    def test_format_event_shows_common_operator_events_without_dict_dump(self):
        cases = [
            (
                "host.found",
                {"host": "192.0.2.10", "status": "up", "scanner": "nmap"},
                "host.found 192.0.2.10 up nmap",
            ),
            (
                "name.resolved",
                {"name": "example.test", "addresses": ["203.0.113.10", "203.0.113.11"]},
                "name.resolved example.test -> 203.0.113.10, 203.0.113.11",
            ),
            (
                "console.output",
                {"source": "job", "text": "JOB  SERIAL\n---  ------\n1    abc"},
                "job output: JOB  SERIAL",
            ),
            (
                "framework.console.output.requested",
                {"source": "job", "text": "JOB  SERIAL\n---  ------\n1    abc"},
                "job output requested: JOB  SERIAL",
            ),
            (
                "framework.console.alert.requested",
                {"source": "portscanner", "level": "alert", "message": "discovered port 443/tcp"},
                "portscanner alert requested alert: discovered port 443/tcp",
            ),
            (
                "plugin.capability.used",
                {"commandlet": "portscanner", "capability": "network.connect", "declared": True},
                "portscanner capability network.connect declared",
            ),
            (
                "plugin.capability.missing",
                {"commandlet": "portscanner", "capability": "db.read:*", "declared": False},
                "portscanner capability db.read:* missing",
            ),
            (
                "framework.trigger.fired",
                {
                    "trigger_id": "runtime.watchdog.network-access-starts-watchdog",
                    "action_command": "watchdog --session-service",
                    "trigger_event_topic": "plugin.capability.used",
                },
                "trigger fired runtime.watchdog.network-access-starts-watchdog",
            ),
            (
                "framework.process.run.requested",
                {"source": "nikto", "argv": ["nikto", "-host", "http://127.0.0.1/"], "timeout": 300.0},
                "nikto process requested: nikto -host http://127.0.0.1/ timeout=300.0",
            ),
            (
                "system.error",
                {"tool": "nikto", "severity": "error", "message": "nikto executable not found"},
                "nikto error: nikto executable not found",
            ),
            (
                "runtime.name.assigned",
                {"target_type": "pipeline", "target_id": "pipeline-1", "name": "client scan"},
                "pipeline pipeline-1 named client scan",
            ),
            (
                "job.failed",
                {
                    "job_id": 376,
                    "started_at": "2026-05-22T10:00:00+00:00",
                    "command": "hostscanner 127.0.0.1",
                    "error": "nmap unavailable",
                },
                "job 376 failed",
            ),
        ]
        for topic, payload, expected in cases:
            with self.subTest(topic=topic):
                text = format_event(Event.new(topic, payload, "framework"))
                self.assertIn(expected, text)
                self.assertNotIn("{", text)

    def test_events_defaults_to_tail_last_25(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            for number in range(30):
                runner.db.publish("topic", {"n": number}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events")
            text = output.getvalue()
            self.assertNotIn("'n': 4", text)
            self.assertIn("'n': 5", text)
            self.assertIn("'n': 29", text)

    def test_events_tail_accepts_last_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            for number in range(5):
                runner.db.publish("topic", {"n": number}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events tail last=2")
            text = output.getvalue()
            self.assertNotIn("'n': 2", text)
            self.assertIn("'n': 3", text)
            self.assertIn("'n': 4", text)

    def test_events_colors_event_ids_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.events.color", "always")
            event = runner.db.publish("plugin.progress.completed", {"commandlet": "hostscanner", "n": 1}, "hostscanner")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "events last=1")
            text = output.getvalue()
            self.assertIn(f"\x1b[94m{event.id}\x1b[0m:", text)
            self.assertIn("\x1b[1;33mhostscanner\x1b[0m", text)

    def test_event_id_prints_event_runtime_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.finish_job(job_id, "failed")
            event = runner.db.publish(
                "job.failed",
                {"job_id": job_id, "command": "hostscanner 127.0.0.1", "error": "boom"},
                "runner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event {event.id}")
            text = output.getvalue()
            self.assertIn(f"Event ID: {event.id}", text)
            self.assertIn("Topic: job.failed", text)
            self.assertIn("Source: runner", text)
            self.assertIn("Created: ", text)
            created = text.split("Created: ", 1)[1].splitlines()[0]
            self.assertRegex(created, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("Job:", text)
            self.assertIn("Commandlet: hostscanner", text)
            self.assertIn("Command: hostscanner 127.0.0.1", text)
            self.assertIn("error: boom", text)

    def test_event_id_reports_unknown_event_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event 999")
            self.assertIn("error: unknown event: 999", output.getvalue())

    def test_event_id_colors_detail_keys_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.events.color", "always")
            runner.registry.varstore.set("display.events.key-color", "green")
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.finish_job(job_id, "failed")
            event = runner.db.publish(
                "job.failed",
                {"job_id": job_id, "commandlet": "hostscanner", "error": "boom"},
                "runner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event {event.id}")
            text = output.getvalue()
            self.assertIn(f"\x1b[33mEvent ID\x1b[0m: \x1b[94m{event.id}\x1b[0m", text)
            self.assertIn("\x1b[32mTopic\x1b[0m: job.failed", text)
            self.assertIn("\x1b[32mCommandlet\x1b[0m: \x1b[1;33mhostscanner\x1b[0m", text)
            self.assertIn("\x1b[33mPayload\x1b[0m:", text)
            self.assertIn("  \x1b[32mcommandlet\x1b[0m: \x1b[1;33mhostscanner\x1b[0m", text)
            self.assertIn("  \x1b[32merror\x1b[0m: boom", text)

    def test_main_version_returns_success(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--version"]), 0)

    def test_main_run_unknown_command_returns_error(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["run", "missing"]), 1)
        self.assertIn("error: unknown commandlet: missing", output.getvalue())

    def test_main_run_without_command_returns_error(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["run"]), 1)
        self.assertIn("error: run requires a command", output.getvalue())

    def test_shutdown_runner_checkpoints_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch.object(runner.db, "checkpoint") as checkpoint:
                shutdown_runner(runner)
            checkpoint.assert_called_once_with()

    def test_repl_checkpoints_on_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("builtins.input", side_effect=["q"]),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                repl(runner)
            checkpoint.assert_called_once_with()

    def test_repl_confirms_keyboard_interrupt_before_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([KeyboardInterrupt, "n", "q"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is KeyboardInterrupt:
                    raise KeyboardInterrupt
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_exits_after_confirmed_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([KeyboardInterrupt, "yes"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is KeyboardInterrupt:
                    raise KeyboardInterrupt
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_confirms_eof_before_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([EOFError, "n", "q"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is EOFError:
                    raise EOFError
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_exits_after_confirmed_eof(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([EOFError, "yes"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is EOFError:
                    raise EOFError
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_confirm_repl_exit_reprompts_until_yes_or_no(self):
        answers = iter(["maybe", "Y"])

        def reader(prompt):
            print(prompt, end="")
            return next(answers)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(reader))
        self.assertIn("please answer yes or no", output.getvalue())

    def test_confirm_repl_exit_accepts_single_yes_keypress(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(key_reader=lambda: "y"))
        self.assertIn("Quit Bywaf? [y/N] y", output.getvalue())

    def test_confirm_repl_exit_accepts_single_no_keypress(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(confirm_repl_exit(key_reader=lambda: "n"))
        self.assertIn("Quit Bywaf? [y/N] n", output.getvalue())

    def test_confirm_repl_exit_reprompts_single_keypress_until_yes_or_no(self):
        answers = iter(["x", "y"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(key_reader=lambda: next(answers)))
        self.assertIn("please press y or n", output.getvalue())

    def test_read_logical_input_joins_backslash_continuations(self):
        state = ShellState()
        with patch("builtins.input", side_effect=["hostscanner \\", "127.0.0.1"]):
            self.assertEqual(read_logical_input(state), "hostscanner \n127.0.0.1")

    def test_dispatch_plugins_lists_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "plugins")
            text = output.getvalue()
            self.assertIn("PLUGIN", text)
            self.assertIn("CMDS", text)
            self.assertIn("WHAT IT DOES", text)
            self.assertIn("discovery", text)
            self.assertIn("Host and target discovery commandlets.", text)

    def test_dispatch_cmds_lists_commandlets_grouped_by_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "cmds")
            text = output.getvalue()
            self.assertIn("PLUGIN", text)
            self.assertIn("COMMANDLET", text)
            self.assertIn("WHAT IT DOES", text)
            self.assertIn("os", text)
            self.assertIn("ls", text)
            self.assertIn("List files in a local directory.", text)

    def test_dispatch_triggers_lists_provider_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "triggers")
            text = output.getvalue()
            self.assertIn("network-access-starts-watchdog", text)
            self.assertIn("plugin.capability.used", text)

    def test_dispatch_cmds_page_uses_system_pager_for_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.display.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.repl.display.sys.stdin.isatty", return_value=True),
                patch("bywaf.repl.display.sys.stdout.isatty", return_value=True),
                patch("bywaf.repl.display.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, "cmds --page")
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/less")
            self.assertFalse(Path(argv[1]).exists())

    def test_start_default_services_launches_session_watchdog_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", None, "running")
            trigger_event = runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": job_id,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
                start_default_services(runner)
            start.assert_called_once_with("watchdog --session-service")
            self.assertEqual(runner.session_service_job_ids, {7})
            state = runner.db.trigger_states()[0]
            self.assertEqual(state["name"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(state["enabled"], 1)
            self.assertEqual(state["last_fired_event_id"], trigger_event.id)
            enabled = runner.db.events_for_topic("framework.trigger.enabled")[0]
            self.assertEqual(enabled.payload["trigger_id"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(enabled.payload["provider"], "runtime.watchdog")
            self.assertEqual(enabled.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(enabled.payload["action_command"], "watchdog --session-service")
            fired = runner.db.events_for_topic("framework.trigger.fired")[0]
            self.assertEqual(fired.payload["trigger_id"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(fired.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(fired.payload["trigger_event_id"], trigger_event.id)
            self.assertEqual(fired.payload["trigger_event_topic"], "plugin.capability.used")

    def test_start_default_services_waits_for_network_capability_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()
            self.assertEqual(runner.session_service_job_ids, set())
            self.assertEqual(len(runner.db.events_for_topic("framework.trigger.enabled")), 1)

    def test_start_default_services_ignores_inactive_network_capability_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", None, "finished")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": job_id,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()

    def test_start_default_services_advances_trigger_cursor_past_non_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            inactive_job = runner.db.record_job("hostscanner old", None, "finished")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": inactive_job,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()
            cursor = runner.trigger_event_cursors["runtime.watchdog.network-access-starts-watchdog"]
            self.assertGreater(cursor, 0)

            active_job = runner.db.record_job("hostscanner 127.0.0.1", None, "running")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": active_job,
                },
                "hostscanner",
            )
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_called_once_with("watchdog --session-service")
            self.assertGreater(runner.trigger_event_cursors["runtime.watchdog.network-access-starts-watchdog"], cursor)

    def test_trigger_payload_equals_predicate_and_foreground_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="dedupe-vulnerabilities",
                    topic="vulnerability.found",
                    action_command="finding_dedupe",
                    action_mode="foreground",
                    payload_equals=(("severity", "high"),),
                )
            ]
            runner.db.publish("vulnerability.found", {"severity": "low"}, "nikto")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_not_called()
            runner.db.publish("vulnerability.found", {"severity": "high"}, "nikto")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_called_once_with("finding_dedupe")

    def test_trigger_background_action_starts_each_matching_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="report-findings",
                    topic="finding.deduped",
                    action_command="finding_report",
                    action_mode="background",
                )
            ]
            first = Event.new("job.requested", {"job_id": 8}, "runner")
            second = Event.new("job.requested", {"job_id": 9}, "runner")
            runner.db.publish("finding.deduped", {"id": "a"}, "finding_dedupe")
            with patch.object(runner, "start_background", return_value=first) as start:
                start_default_services(runner)
            start.assert_called_once_with("finding_report")
            runner.db.publish("finding.deduped", {"id": "b"}, "finding_dedupe")
            with patch.object(runner, "start_background", return_value=second) as start:
                start_default_services(runner)
            start.assert_called_once_with("finding_report")

    def test_provider_scoped_trigger_ids_prevent_cursor_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_trigger = TriggerSpec(
                name="same-local-name",
                topic="provider.b.event",
                action_command="provider_b_action",
                action_mode="background",
            )
            second_trigger = TriggerSpec(
                name="same-local-name",
                topic="provider.a.event",
                action_command="provider_a_action",
                action_mode="background",
            )
            runner.registry.triggers = []
            runner.registry.trigger_providers.clear()
            runner.registry.add_triggers("provider.a", (second_trigger,))
            runner.registry.add_triggers("provider.b", (first_trigger,))
            runner.db.publish("provider.b.event", {"id": "older"}, "provider_b")
            runner.db.publish("provider.a.event", {"id": "newer"}, "provider_a")
            event = Event.new("job.requested", {"job_id": 10}, "runner")

            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)

            start.assert_any_call("provider_a_action")
            start.assert_any_call("provider_b_action")
            self.assertEqual(start.call_count, 2)
            states = {str(row["name"]): row for row in runner.db.trigger_states()}
            self.assertIn("provider.a.same-local-name", states)
            self.assertIn("provider.b.same-local-name", states)

    def test_trigger_suppresses_self_trigger_loop_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="dedupe-loop-guard",
                    topic="finding.deduped",
                    action_command="finding_dedupe",
                    action_mode="foreground",
                )
            ]
            runner.db.publish("finding.deduped", {"id": "a"}, "finding_dedupe")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_not_called()

    def test_shutdown_runner_audits_trigger_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch.object(runner.db, "checkpoint"):
                start_default_services(runner)
                shutdown_runner(runner)
            disabled = runner.db.events_for_topic("framework.trigger.disabled")[0]
            self.assertEqual(disabled.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(disabled.payload["topic"], "plugin.capability.used")

    def test_dispatch_list_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "list")
            self.assertIn("error: unknown command or commandlet: list", output.getvalue())

    def test_dispatch_topics_accepts_prefix_on_empty_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "topics plugins")
            self.assertIn("no matching topics: plugins", output.getvalue())

    def test_dispatch_topics_filters_by_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "test")
            runner.db.publish("port.open", {"port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "topics host")
            self.assertIn("host.found", output.getvalue())
            self.assertNotIn("port.open", output.getvalue())

    def test_extract_startup_project_peels_project_selector(self):
        project, argv = extract_startup_project(["project=client-a", "--new", "repl"])
        self.assertEqual(project, "client-a")
        self.assertEqual(argv, ["--new", "repl"])
        project, argv = extract_startup_project(["--new", "project=client-b"])
        self.assertEqual(project, "client-b")
        self.assertEqual(argv, ["--new"])

    def test_project_use_refuses_active_jobs_and_mentions_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                runner = make_runner(Path(tmp, "adhoc.sqlite3"))
                state = ShellState()
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "project new name=client-a", state)
                runner.db.record_job("hostscanner 127.0.0.1&", None, "running")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "project use name=client-a", state)
                text = output.getvalue()
                self.assertIn("cannot switch to project=client-a while 1 job(s) are active", text)
                self.assertIn("project use name=client-a --force", text)
                self.assertEqual(runner.db.path, Path(tmp, "adhoc.sqlite3"))

    def test_project_use_force_stops_active_jobs_and_switches_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                runner = make_runner(Path(tmp, "adhoc.sqlite3"))
                state = ShellState()
                runner.registry.varstore.set("global.marker", "old")
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "project new name=client-a", state)
                old_db = runner.db
                job_id = old_db.record_job("hostscanner 127.0.0.1&", None, "running")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "project use name=client-a --force", state)
                self.assertIn("stopped 1 active job(s)", output.getvalue())
                self.assertIn("using project=client-a", output.getvalue())
                self.assertEqual(runner.db.path, Path(tmp, ".bywaf", "projects", "client-a", "bywaf.sqlite3"))
                self.assertEqual(state.history_path, Path(tmp, ".bywaf", "projects", "client-a", "history.bywaf"))
                self.assertIsNone(runner.registry.varstore.get("global.marker"))
                self.assertEqual(old_db.jobs(active_only=False)[0]["status"], "killed")
                events = old_db.events_for_topic("project.switch.force_stopped")
                self.assertEqual(events[-1].payload["count"], 1)
                self.assertEqual(events[-1].payload["jobs"][0]["job_id"], job_id)

    def test_use_context_scopes_short_vars_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "var targets=127.0.0.1", state)
                dispatch_repl_line(runner, "use global", state)
                dispatch_repl_line(runner, "var target=global", state)
            self.assertEqual(runner.registry.varstore.get("hostscanner.targets"), "127.0.0.1")
            self.assertEqual(runner.registry.varstore.get("target"), "global")

    def test_vars_name_prints_one_variable_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "var global.proxy=http://127.0.0.1:8080", state)
                dispatch_repl_line(runner, "var global.proxy", state)
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "var targets=127.0.0.1", state)
                dispatch_repl_line(runner, "var targets", state)
                dispatch_repl_line(runner, "var missing", state)
            text = output.getvalue()
            self.assertIn("global.proxy=http://127.0.0.1:8080", text)
            self.assertIn("hostscanner.targets=127.0.0.1", text)
            self.assertIn("error: variable not set: hostscanner.missing", text)

    def test_vars_plain_password_assignment_is_not_implicitly_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "var password=supersecret", state)
                dispatch_repl_line(runner, "var password", state)
            text = output.getvalue()
            self.assertEqual(runner.registry.varstore.get("password"), "supersecret")
            self.assertIn("password=supersecret", text)

    def test_vars_command_name_is_not_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "vars password=supersecret", ShellState())
            self.assertIn("error: unknown command or commandlet: vars", output.getvalue())
            self.assertIsNone(runner.registry.varstore.get("password"))

    def test_vars_explicit_secret_assignment_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var --secret session.ticket=supersecret", state)
                dispatch_repl_line(runner, "var session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED] fingerprint=hmac-sha256:", text)

    def test_vars_secret_flag_before_equals_marks_assignment_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var session.ticket --secret=supersecret", state)
                dispatch_repl_line(runner, "var session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED] fingerprint=hmac-sha256:", text)

    def test_vars_empty_explicit_secret_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.commands.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var --secret pw=", state)
                dispatch_repl_line(runner, "var pw", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for pw: ")
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("pw=[REDACTED] fingerprint=hmac-sha256:", text)

    def test_vars_redacted_block_uses_hidden_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(secret_values={"pw": "block-secret"})
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.commands.getpass.getpass") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var --secret pw=[REDACTED]", state)
                dispatch_repl_line(runner, "var pw", state)
            getpass.assert_not_called()
            text = output.getvalue()
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "block-secret")
            self.assertNotIn("block-secret", text)
            self.assertIn("pw=[REDACTED] fingerprint=hmac-sha256:", text)

    def test_vars_empty_secret_flag_before_equals_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.commands.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var session.ticket --secret=", state)
                dispatch_repl_line(runner, "var session.ticket", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for session.ticket: ")
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("session.ticket=[REDACTED] fingerprint=hmac-sha256:", text)

    def test_vars_can_color_names_and_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "yellow")
            runner.registry.varstore.set("display.vars.value-color", "bright-blue")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "var target=127.0.0.1", state)
                dispatch_repl_line(runner, "var target", state)
                dispatch_repl_line(runner, "var target", state)
            self.assertIn("\x1b[33mtarget\x1b[0m=\x1b[94m127.0.0.1\x1b[0m", output.getvalue())

    def test_vars_accept_extended_color_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "rgb:80,180,90")
            runner.registry.varstore.set("display.vars.value-color", "ansi:34")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "var target=127.0.0.1", state)
                dispatch_repl_line(runner, "var target", state)
            self.assertIn("\x1b[38;2;80;180;90mtarget\x1b[0m=\x1b[38;5;34m127.0.0.1\x1b[0m", output.getvalue())

    def test_vars_ignore_invalid_extended_color_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "rgb:999,0,0")
            runner.registry.varstore.set("display.vars.value-color", "ansi:999")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "var target=127.0.0.1", state)
                dispatch_repl_line(runner, "var target", state)
            self.assertIn("target=127.0.0.1", output.getvalue())
            self.assertNotIn("\x1b[", output.getvalue())

    def test_vars_secret_redaction_uses_warning_style_when_colored(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            output = io.StringIO()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "var --secret session.ticket=supersecret", state)
            self.assertIn("\x1b[37;48;5;52m[REDACTED]\x1b[0m", output.getvalue())
            self.assertNotIn("supersecret", output.getvalue())

    def test_vars_secret_assignment_respects_active_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "use ssh_probe", state)
                dispatch_repl_line(runner, "var --secret password=supersecret", state)
            stored = runner.registry.varstore.get("ssh_probe.password")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))

    def test_vars_secret_assignment_persists_and_hydrates_from_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = make_runner(db_path)
            with (
                patch("bywaf.repl.commands.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(first, "var --secret ssh_probe.password=supersecret", ShellState())

            second = make_runner(db_path)
            stored = second.registry.varstore.get("ssh_probe.password")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(second.registry.secrets.is_ref(stored))
            self.assertEqual(second.registry.secrets.get(stored), "supersecret")

    def test_dispatch_ls_lists_local_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "file.txt").write_text("x")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"ls {tmp}")
            self.assertIn("file.txt", output.getvalue())

    def test_dispatch_ls_file_prints_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("x")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"ls {path}")
            self.assertEqual(output.getvalue(), "file.txt\n")

    def test_dispatch_cat_and_less_print_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("hello\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            cat_output = io.StringIO()
            less_output = io.StringIO()
            with contextlib.redirect_stdout(cat_output):
                dispatch_repl_line(runner, f"cat {path}")
            with contextlib.redirect_stdout(less_output):
                dispatch_repl_line(runner, f"less {path}")
            self.assertEqual(cat_output.getvalue(), "hello\n")
            self.assertEqual(less_output.getvalue(), "hello\n")

    def test_less_uses_system_pager_when_interactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file.txt")
            path.write_text("hello\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.display.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.repl.display.sys.stdin.isatty", return_value=True),
                patch("bywaf.repl.display.sys.stdout.isatty", return_value=True),
                patch("bywaf.repl.display.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, f"less {path}")
            run.assert_called_once_with(["/usr/bin/less", str(path)], check=False)

    def test_list_action_page_uses_system_pager_for_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            with (
                patch("bywaf.repl.display.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.repl.display.sys.stdin.isatty", return_value=True),
                patch("bywaf.repl.display.sys.stdout.isatty", return_value=True),
                patch("bywaf.repl.display.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, "job list --page")
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/less")
            self.assertFalse(Path(argv[1]).exists())

    def test_dispatch_unknown_command_prints_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "missing")
            self.assertIn("error: unknown command or commandlet: missing", output.getvalue())

    def test_dispatch_help_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "?")
            self.assertIn("plugins", output.getvalue())
            self.assertIn("cmds", output.getvalue())
            self.assertIn("load script=<path>", output.getvalue())

    def test_dispatch_help_colors_commands_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.help.color", "always")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "?")
            self.assertIn("\x1b[32mplugins", output.getvalue())

    def test_dispatch_runs_lists_command_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.publish(
                "artifact.attached",
                {"artifact_id": "artifact-1", "job_id": job_id},
                "framework",
                pipeline_id="p",
                command_run_id="r",
            )
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "runs")
            text = output.getvalue()
            self.assertIn("RUN", text)
            self.assertIn("ARTIFACTS", text)
            self.assertRegex(text, r"\n1\s+r\s+active\s+\s*1\s+p\s+hostscanner\s+1\s+1\s+")

    def test_info_shows_active_runtime_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "info")
            text = output.getvalue()
            self.assertIn("Jobs (1)", text)
            self.assertIn("Pipelines (1)", text)
            self.assertIn("Runs (1)", text)
            self.assertIn("ARTIFACTS", text)

    def test_runtime_names_display_in_listings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("runtime.name.assigned", {"target_type": "run", "target_id": "r", "name": "run name"}, "framework", command_run_id="r")
            runner.db.publish("runtime.name.assigned", {"target_type": "pipeline", "target_id": "p", "name": "pipeline name"}, "framework", pipeline_id="p")
            runner.db.publish("runtime.name.assigned", {"target_type": "job", "target_id": str(job_id), "name": "job name"}, "framework")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "runs")
                dispatch_repl_line(runner, "pipelines")
                dispatch_repl_line(runner, "jobs")
                dispatch_repl_line(runner, f"event job={job_id}")
                dispatch_repl_line(runner, "job show 1")
                dispatch_repl_line(runner, "pipeline show 1")
            text = output.getvalue()
            self.assertIn("run name", text)
            self.assertIn("pipeline name", text)
            self.assertIn("job name", text)
            self.assertIn("commandlet=hostscanner", text)
            self.assertIn("command=hostscanner 127.0.0.1", text)
            self.assertIn("ARTIFACTS", text)

    def test_dispatch_runs_defaults_to_active_unless_all_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner done", 123, "finished")
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "runs")
            self.assertIn("no active runs", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "runs --all")
            self.assertRegex(output.getvalue(), r"\n1\s+r\s+completed\s+\s*1\s+p\s+hostscanner\s+1\s+0\s+")

    def test_make_runner_marks_dead_runtime_jobs_stale_on_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            db = EventStore(db_path)
            job_id = db.record_job("hostscanner 127.0.0.1", 99999999, "running")
            db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner = make_runner(db_path)
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "stale")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipelines")
            self.assertIn("no active pipelines", output.getvalue())

    def test_jobs_alias_runs_job_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "jobs")
            self.assertIn("ARTIFACTS", output.getvalue())
            self.assertRegex(output.getvalue(), r"\n1\s+[0-9a-f]{32}\s+active\s+123\s+running\s+0\s+")
            self.assertIn("hostscanner 127.0.0.1", output.getvalue())

    def test_jobs_all_marks_active_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("active", 123, "running")
            runner.db.record_job("old", 456, "finished")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "jobs --all")
            text = output.getvalue()
            self.assertRegex(text, r"\n1\s+[0-9a-f]{32}\s+active\s+123\s+running\s+0\s+")
            self.assertRegex(text, r"\n2\s+[0-9a-f]{32}\s+completed\s+456\s+finished\s+0\s+")

    def test_jobs_all_can_use_long_active_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.listing.active-format", "long")
            runner.db.record_job("active", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "jobs --all")
            self.assertIn("active since ", output.getvalue())
            self.assertRegex(output.getvalue(), r"\n1\s+[0-9a-f]{32}\s+active since ")

    def test_pipelines_alias_runs_pipeline_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipelines")
            text = output.getvalue()
            self.assertIn("ARTIFACTS", text)
            self.assertRegex(text, rf"\n1\s+pipe-1\s+active\s+\s*{job_id}\s+running\s+1\s+0\s+0\s+")

    def test_pipeline_list_defaults_to_active_unless_all_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner done", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="finished-pipe",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline list")
            self.assertIn("no active pipelines", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline list --all")
            self.assertIn("finished-pipe", output.getvalue())

    def test_job_cancel_records_soft_cancellation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"job cancel {job_id}")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"cancel requested for job {job_id}", output.getvalue())

    def test_pause_resume_stop_commands_record_job_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"pause job={job_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"resume --listonly job={job_id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"stop job={job_id}")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())
            self.assertIn(f"queued resume actions for job {job_id}", output.getvalue())
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_pause_resume_stop_commands_accept_run_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="portscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("pause run=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume --listonly run=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume run=run-1")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())
            self.assertIn("run.pause.requested run=run-1", output.getvalue())
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "running")

    def test_signal_records_plugin_scoped_live_control_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("signal run=run-1 prune targets=192.168.1.0/24 reason=user-request")
                process_framework_requests(runner, ShellState())
            signal_event = runner.db.events_for_topic("runtime.signal.requested")[0]
            self.assertEqual(signal_event.command_run_id, "run-1")
            self.assertEqual(signal_event.payload["target_type"], "run")
            self.assertEqual(signal_event.payload["action"], "prune")
            self.assertEqual(signal_event.payload["args"]["targets"], "192.168.1.0/24")
            self.assertIn("signal requested for run=run-1 action=prune mode=soft", output.getvalue())

    def test_signal_pause_applies_framework_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"signal job={job_id} pause")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.events_for_topic("runtime.signal.requested")[0].payload["action"], "pause")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "pausing")
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())

    def test_runtime_control_uses_narrow_store_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"pause job={job_id}")
                process_framework_requests(runner, ShellState())
            capabilities = {
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            }
            self.assertIn("framework.job.control", capabilities)
            self.assertNotIn("db.raw", capabilities)

    def test_signal_accepts_job_and_run_serials_but_rejects_pipeline_serials(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            job_serial = runner.db.job_serial(job_id)
            self.assertIsNotNone(job_serial)
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-serial",
                command_run_id="run-serial",
                commandlet="portscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"signal serial={job_serial} mute")
                process_framework_requests(runner, ShellState())
                runner.execute("signal serial=run-serial verbosity level=debug")
                process_framework_requests(runner, ShellState())
                dispatch_repl_line(runner, "signal serial=pipeline-serial mute")
            events = runner.db.events_for_topic("runtime.signal.requested")
            self.assertEqual(events[0].payload["target_type"], "job")
            self.assertEqual(events[0].payload["target_id"], str(job_id))
            self.assertEqual(events[1].payload["target_type"], "run")
            self.assertEqual(events[1].payload["target_id"], "run-serial")
            self.assertIn("error: signal serial= must resolve to a job or run, not a pipeline", output.getvalue())

    def test_job_end_defaults_to_cooperative_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job end {job_id}")
            kill.assert_not_called()
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_job_kill_hard_sends_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job kill --hard {job_id}")
            self.assertEqual(kill.call_args.args[1].name, "SIGKILL")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "killed")

    def test_pipeline_cancel_records_soft_cancellation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("pipeline", 123, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("pipeline cancel pipe-1")
                process_framework_requests(runner, ShellState())
            self.assertTrue(runner.db.cancellation_requested(pipeline_id="pipe-1"))
            self.assertIn("cancel requested for pipeline pipe-1", output.getvalue())

    def test_pipeline_kill_defaults_to_cooperative_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("pipeline", 99999, "running")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("pipeline kill pipe-1")
            kill.assert_not_called()
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_convenience_end_and_kill_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"end job={job_id}")
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"kill --hard job={job_id}")
            self.assertEqual(kill.call_args.args[1].name, "SIGKILL")



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
