"""Tests for app dispatch behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from bywaf.artifacts import artifact_store_for_event_store
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
from bywaf.plugins.network.nmap_backend import NmapPort
from bywaf.projects import ProjectPaths
from bywaf.specs import TriggerSpec
from bywaf.triggers import start_default_services
class AppDispatchTests(unittest.TestCase):
    def test_build_parser_accepts_exec(self):
        parser = build_parser()
        args = parser.parse_args(["exec", "echo", "hello"])
        self.assertEqual(args.subcommand, "exec")
        self.assertEqual(args.command, ["echo", "hello"])

    def test_route_direct_commandlet_argv(self):
        from bywaf.app import route_direct_commandlet_argv

        self.assertEqual(route_direct_commandlet_argv(["hostscanner", "127.0.0.1"]), ["cmd", "hostscanner", "127.0.0.1"])
        self.assertEqual(route_direct_commandlet_argv(["exec", "echo", "hello"]), ["exec", "echo", "hello"])

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
        forced, resource, catalog_path = parse_load_spec("--force plugin=example")
        self.assertTrue(forced)
        self.assertEqual(resource, "plugin=example")
        self.assertIsNone(catalog_path)

    def test_parse_load_spec_accepts_catalog_path(self):
        forced, resource, catalog_path = parse_load_spec("--force plugin=example path=lab/example")
        self.assertTrue(forced)
        self.assertEqual(resource, "plugin=example")
        self.assertEqual(catalog_path, "lab/example")

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

    def test_event_filters_topic_by_payload_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 80, "protocol": "tcp"}, "test")
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open host=192.0.2.20")
            text = output.getvalue()
            self.assertNotIn("192.0.2.10", text)
            self.assertIn("192.0.2.20:443/tcp", text)

    def test_event_filters_nested_host_and_sorts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("finding.candidate", {"target": {"host": "192.0.2.20"}, "port": 443}, "test")
            runner.db.publish("finding.candidate", {"target": {"host": "192.0.2.10"}, "port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event finding.candidate host=192.0.2.10,192.0.2.20 sort=host")
            lines = [line for line in output.getvalue().splitlines() if "finding.candidate" in line]
            self.assertIn("192.0.2.10", lines[0])
            self.assertIn("192.0.2.20", lines[1])

    def test_event_filters_support_include_exclude_and_network_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.168.50.10", "port": 80}, "test")
            runner.db.publish("port.open", {"host": "192.168.50.130", "port": 80}, "test")
            runner.db.publish("port.open", {"host": "192.168.51.20", "port": 443}, "test")
            runner.db.publish("port.open", {"host": "198.51.100.10", "port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(
                    runner,
                    "event port.open host=192.168.50.0/24,!192.168.50.1-128 port=80",
                )
            text = output.getvalue()
            self.assertNotIn("192.168.50.10", text)
            self.assertIn("192.168.50.130:80", text)
            self.assertNotIn("192.168.51.20", text)
            self.assertNotIn("198.51.100.10", text)

    def test_step_without_id_lists_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step")
            text = output.getvalue()
            self.assertIn("STEP", text)
            self.assertIn("STATUS", text)

    def test_exec_without_shell_command_prints_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "exec")
            text = output.getvalue()
            self.assertIn("Command: exec <argv...>", text)
            self.assertIn("Usage:   exec <argv...>", text)

    def test_exec_runs_argv_without_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            completed = subprocess.CompletedProcess(["echo", "hello world"], 0)
            with patch("bywaf.repl.command_exec.subprocess.run", return_value=completed) as run:
                dispatch_repl_line(runner, "exec echo 'hello world'")

            run.assert_called_once_with(["echo", "hello world"], check=False)
            events = runner.events.events_matching(topic="shell.exec.completed")
            self.assertEqual(events[-1].payload["argv"], ["echo", "hello world"])

    def test_step_inspects_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="p",
                command_run_id="r",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step 1")
            text = output.getvalue()
            self.assertIn("Variables:", text)
            self.assertIn("test.marker=1", text)
            self.assertIn("host.found 127.0.0.1", text)

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

    def test_events_use_semantic_display_roles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.host", "bold green")
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[1;32m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_accept_escaped_hex_display_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, r"set display/style.host=\#00ff00")
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[38;2;0;255;0m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_accept_quoted_hex_display_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, 'set display/style.host="#00ff00"')
                dispatch_repl_line(runner, "event port.open")
            self.assertIn("\x1b[38;2;0;255;0m192.0.2.10\x1b[0m:443/tcp", output.getvalue())

    def test_events_style_quoted_string_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.string", "bold yellow")
            runner.db.publish("example.topic", {"message": "quoted value"}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event example.topic")
            self.assertIn("\x1b[1;33m'quoted value'\x1b[0m", output.getvalue())

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
            self.assertRegex(created, r"\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
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

    def test_main_direct_unknown_commandlet_returns_error(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["missing"]), 1)
        self.assertIn("error: unknown commandlet: missing", output.getvalue())

    def test_main_exec_without_command_returns_error(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["exec"]), 1)
        self.assertIn("error: exec requires a command", output.getvalue())

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
            self.assertIn("network-access-start", text)
            self.assertIn("plugin.capability", text)

    def test_dispatch_cmds_page_uses_system_pager_for_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((40, 4))),
                patch("bywaf.pager.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, "cmds --page")
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/less")
            self.assertEqual(argv[1], "-R")
            self.assertFalse(Path(argv[2]).exists())

    def test_dispatch_cmds_page_ignores_pager_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((40, 4))),
                patch("bywaf.pager.subprocess.run", side_effect=KeyboardInterrupt),
            ):
                dispatch_repl_line(runner, "cmds --page")

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
                old_job = old_db.job(job_id)
                assert old_job is not None
                self.assertEqual(old_job["status"], "killed")
                events = old_db.events_for_topic("project.switch.force_stopped")
                self.assertEqual(events[-1].payload["count"], 1)
                self.assertEqual(events[-1].payload["jobs"][0]["job_id"], job_id)

    def test_project_archive_includes_project_state_and_artifact_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_dir = root / ".bywaf" / "projects" / "client-a"
            project_dir.mkdir(parents=True)
            paths = ProjectPaths(
                name="client-a",
                root=root / ".bywaf" / "projects",
                path=project_dir,
                database=project_dir / "bywaf.sqlite3",
                config=project_dir / "config.toml",
                history=project_dir / "history.bywaf",
            )
            paths.config.write_text("[variables]\n", encoding="utf-8")
            paths.history.write_text("set target=127.0.0.1\n", encoding="utf-8")
            runner = make_runner(paths.database, project=paths)
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "test")
            source = project_dir / "artifact.txt"
            source.write_text("artifact body", encoding="utf-8")
            artifact_store_for_event_store(runner.db).attach_file(source, commandlet="test")

            archive = root / "client-a.zip"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"project archive file={archive}", ShellState())

            self.assertIn("archived project=client-a", output.getvalue())
            self.assertTrue(archive.exists())
            with zipfile.ZipFile(archive) as zipped:
                names = set(zipped.namelist())
                self.assertIn("bywaf.sqlite3", names)
                self.assertIn("bywaf.artifacts.sqlite3", names)
                self.assertIn("config.toml", names)
                self.assertIn("history.bywaf", names)
                manifest = json.loads(zipped.read("bywaf-archive-manifest.json"))
            self.assertEqual(manifest["schema"], "bywaf.project-archive.v1")
            self.assertEqual(manifest["project"], "client-a")
            self.assertEqual({item["path"] for item in manifest["files"]}, names - {"bywaf-archive-manifest.json"})
            events = runner.db.events_for_topic("project.archived")
            self.assertEqual(events[-1].payload["file"], str(archive))

    def test_project_archive_requires_active_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "adhoc.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"project archive file={Path(tmp, 'archive.zip')}", ShellState())
            self.assertIn("project archive requires an active project", output.getvalue())

    def test_use_context_scopes_short_vars_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "set targets=127.0.0.1", state)
                dispatch_repl_line(runner, "use global", state)
                dispatch_repl_line(runner, "set target=global", state)
            self.assertEqual(runner.registry.varstore.get("discovery/hostscanner.targets"), "127.0.0.1")
            self.assertEqual(runner.registry.varstore.get("target"), "global")

    def test_vars_name_prints_one_variable_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set global.proxy=http://127.0.0.1:8080", state)
                dispatch_repl_line(runner, "set global.proxy", state)
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "set targets=127.0.0.1", state)
                dispatch_repl_line(runner, "set targets", state)
                dispatch_repl_line(runner, "set missing", state)
            text = output.getvalue()
            self.assertIn("global.proxy=http://127.0.0.1:8080", text)
            self.assertIn("discovery/hostscanner.targets=127.0.0.1", text)
            self.assertIn("error: variable not set: discovery/hostscanner.missing", text)

    def test_setg_sets_global_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "setg proxy=http://127.0.0.1:8080", ShellState())
                dispatch_repl_line(runner, "setg proxy", ShellState())
            self.assertEqual(runner.registry.varstore.get("global.proxy"), "http://127.0.0.1:8080")
            self.assertIn("global.proxy=http://127.0.0.1:8080", output.getvalue())

    def test_pending_catalog_variable_warns_and_survives_default_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set scanners/example.answer=99", ShellState())
            self.assertEqual(runner.registry.varstore.get("scanners/example.answer"), "99")
            self.assertIn(
                "warning: scanners/example is not loaded; storing scanners/example.answer until that commandlet is loaded",
                output.getvalue(),
            )

    def test_vars_plain_password_assignment_is_not_implicitly_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set password=supersecret", state)
                dispatch_repl_line(runner, "set password", state)
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
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret session.ticket=supersecret", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_secret_flag_before_equals_marks_assignment_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set session.ticket --secret=supersecret", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_empty_explicit_secret_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command_vars.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret pw=", state)
                dispatch_repl_line(runner, "set pw", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for pw: ")
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("pw=[REDACTED#", text)

    def test_vars_redacted_block_uses_hidden_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(secret_values={"pw": "block-secret"})
            output = io.StringIO()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command_vars.getpass.getpass") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret pw=[REDACTED]", state)
                dispatch_repl_line(runner, "set pw", state)
            getpass.assert_not_called()
            text = output.getvalue()
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "block-secret")
            self.assertNotIn("block-secret", text)
            self.assertIn("pw=[REDACTED#", text)

    def test_vars_empty_secret_flag_before_equals_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command_vars.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set session.ticket --secret=", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for session.ticket: ")
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_can_color_names_and_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "yellow")
            runner.registry.varstore.set("display.vars.value-color", "bright-blue")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
                dispatch_repl_line(runner, "set target", state)
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
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
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
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
            self.assertIn("target=127.0.0.1", output.getvalue())
            self.assertNotIn("\x1b[", output.getvalue())

    def test_vars_secret_redaction_uses_warning_style_when_colored(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            output = io.StringIO()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret session.ticket=supersecret", state)
            self.assertIn("\x1b[37;48;5;52m[REDACTED#", output.getvalue())
            self.assertNotIn("supersecret", output.getvalue())

    def test_vars_secret_assignment_respects_active_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "use ssh_probe", state)
                dispatch_repl_line(runner, "set --secret password=supersecret", state)
            stored = runner.registry.varstore.get("network/ssh_probe.password")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))

    def test_vars_secret_assignment_persists_and_hydrates_from_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = make_runner(db_path)
            with (
                patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(first, "set --secret ssh_probe.password=supersecret", ShellState())

            second = make_runner(db_path)
            stored = second.registry.varstore.get("network/ssh_probe.password")
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
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((4, 1))),
                patch("bywaf.pager.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, f"less {path}")
            run.assert_called_once_with(["/usr/bin/less", "-R", str(path)], check=False)

    def test_list_action_page_uses_system_pager_for_generated_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            for index in range(8):
                runner.db.record_job(f"hostscanner 127.0.0.{index}", 123 + index, "running")
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((40, 4))),
                patch("bywaf.pager.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, "job --page")
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/less")
            self.assertEqual(argv[1], "-R")
            self.assertFalse(Path(argv[2]).exists())

    def test_page_prints_inline_when_generated_output_fits_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((240, 80))),
                patch("bywaf.pager.subprocess.run") as run,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "job --page")
            run.assert_not_called()
            self.assertIn("hostscanner", output.getvalue())

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
            self.assertIn("script", output.getvalue())

    def test_dispatch_help_colors_commands_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.help.color", "always")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "?")
            self.assertIn("\x1b[32mplugins", output.getvalue())

    def test_dispatch_steps_lists_command_runs(self):
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
                dispatch_repl_line(runner, "step")
            text = output.getvalue()
            self.assertIn("STEP", text)
            self.assertIn("ART", text)
            self.assertRegex(text, r"\n1\s+active/running\s+1\s+hostscanner\s+2\s+1\s+")
            self.assertEqual(text.count("hostscanner"), 1)

    def test_runtime_lists_filter_by_host_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_one = runner.db.record_job("hostscanner 192.0.2.10", 123, "running")
            job_two = runner.db.record_job("hostscanner 192.0.2.20", 124, "running")
            runner.db.record_command_run_vars(
                job_id=job_one,
                pipeline_id="pipe-a",
                command_run_id="step-a",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.record_command_run_vars(
                job_id=job_two,
                pipeline_id="pipe-b",
                command_run_id="step-b",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish("host.found", {"host": "192.0.2.10"}, "hostscanner", pipeline_id="pipe-a", command_run_id="step-a")
            runner.db.publish("host.found", {"host": "192.0.2.20"}, "hostscanner", pipeline_id="pipe-b", command_run_id="step-b")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")
            text = output.getvalue()
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)
            self.assertNotIn("pipe-a", text)
            self.assertNotIn("step-a", text)

    def test_runtime_filter_lists_include_finished_scopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-done",
                command_run_id="step-done",
                commandlet="portscanner",
                values={"network/portscanner.host": "192.0.2.20"},
            )
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner", pipeline_id="pipe-done", command_run_id="step-done")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")
            text = output.getvalue()
            self.assertIn("portscanner", text)
            self.assertIn("host=192.0.2.20", text)
            self.assertIn("PIPELINE", text)
            self.assertIn("STEP", text)

    def test_runtime_filters_match_foreground_portscanner_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("192.0.2.10", 80, "tcp", "open", "http")],
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "network/portscanner host=192.0.2.10 port=80", state)
                    dispatch_repl_line(runner, "job host=192.0.2.10", state)
                    dispatch_repl_line(runner, "step host=192.0.2.10", state)
                    dispatch_repl_line(runner, "pipeline host=192.0.2.10", state)
            text = output.getvalue()
            self.assertIn("network/portscanner", text)
            self.assertIn("host=192.0.2", text)
            self.assertIn("STEP", text)
            self.assertIn("PIPELINE", text)

    def test_ports_defaults_to_latest_productive_portscanner_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.10"},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp", "service": "http", "reason": "syn-ack"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            new_job = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=new_job,
                pipeline_id="new-pipeline",
                command_run_id="new-step",
                commandlet="network/portscanner",
                values={"network/portscanner.host": "192.0.2.20"},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp", "service": "https", "reason": "syn-ack"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports")
            text = output.getvalue()
            self.assertIn(f"latest portscanner job={new_job}", text)
            self.assertIn("grouped by host ascending (use sort=-host to sort descending)", text)
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)

    def test_ports_all_true_shows_historical_port_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            old_job = runner.db.record_job("network/portscanner host=192.0.2.10 port=80", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=old_job,
                pipeline_id="old-pipeline",
                command_run_id="old-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.10", "port": 80, "protocol": "tcp"},
                "portscanner",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            new_job = runner.db.record_job("network/portscanner host=192.0.2.20 port=443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=new_job,
                pipeline_id="new-pipeline",
                command_run_id="new-step",
                commandlet="network/portscanner",
                values={},
            )
            runner.db.publish(
                "port.open",
                {"host": "192.0.2.20", "port": 443, "protocol": "tcp"},
                "portscanner",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports all=true sort=event")
                dispatch_repl_line(runner, "ports all=true sort=-event")
            text = output.getvalue()
            self.assertIn("all port.open events", text)
            self.assertIn("sorted by event ascending (use sort=-event to sort descending)", text)
            self.assertIn("sorted by event descending (use sort=event to sort ascending)", text)
            self.assertIn("192.0.2.10", text)
            self.assertIn("192.0.2.20", text)

    def test_ports_filters_latest_scan_by_host_and_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner host=192.0.2.0/24 port=80,443", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline",
                command_run_id="step",
                commandlet="network/portscanner",
                values={},
            )
            for host, port in (("192.0.2.10", 80), ("192.0.2.20", 443), ("192.0.2.30", 22)):
                runner.db.publish(
                    "port.open",
                    {"host": host, "port": port, "protocol": "tcp"},
                    "portscanner",
                    pipeline_id="pipeline",
                    command_run_id="step",
                )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "ports host=192.0.2.0/24,!192.0.2.1-15 port=443")
            text = output.getvalue()
            self.assertIn("192.0.2.20", text)
            self.assertNotIn("192.0.2.10", text)
            self.assertNotIn("192.0.2.30", text)

    def test_builtin_filters_expand_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("port.open", {"host": "192.0.2.20", "port": 443}, "portscanner")
            dispatch_repl_line(runner, "set A=192.0.2.20")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "event port.open host=$A")
            self.assertIn("192.0.2.20:443", output.getvalue())

    def test_builtin_expansion_preview_honors_display_mode(self):
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
            with patch("bywaf.repl.command_vars.load_or_create_fingerprint_key", return_value=b"k" * 32):
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
            self.assertIn("Steps (1)", text)
            self.assertIn("ART", text)

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
                dispatch_repl_line(runner, "step")
                dispatch_repl_line(runner, "pipeline")
                dispatch_repl_line(runner, "job")
                dispatch_repl_line(runner, f"event job={job_id}")
                dispatch_repl_line(runner, "job 1")
                dispatch_repl_line(runner, "pipeline 1")
            text = output.getvalue()
            self.assertIn("run name", text)
            self.assertIn("pipeline name", text)
            self.assertIn("job name", text)
            self.assertIn("commandlet=hostscanner", text)
            self.assertIn("args=127.0.0.1", text)
            self.assertIn("ART", text)

    def test_job_show_includes_recorded_commandlet_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("network/portscanner", 123, "failed")
            runner.db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="network/portscanner",
                values={"test.marker": "1"},
            )
            runner.db.publish(
                "command.run.arguments",
                {"args": ["host=192.0.2.10", "ports=80,443", 'arguments="-Pn -sT"']},
                "framework",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"job {job_id}")

            text = output.getvalue()
            self.assertIn("commandlet=network/portscanner", text)
            self.assertNotIn(" command=", text)
            self.assertIn("args=host=192.0.2.10 ports=80,443", text)
            self.assertIn("'arguments=\"-Pn -sT\"'", text)

    def test_job_show_accepts_durable_serial_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            serial = runner.db.job_serial(job_id)
            assert serial is not None

            direct_output = io.StringIO()
            selector_output = io.StringIO()
            with contextlib.redirect_stdout(direct_output):
                dispatch_repl_line(runner, f"job {serial}")
            with contextlib.redirect_stdout(selector_output):
                dispatch_repl_line(runner, f"job serial={serial}")

            self.assertIn(f"serial={serial.split('-', 1)[1][:8]}", direct_output.getvalue())
            self.assertIn("commandlet=hostscanner", direct_output.getvalue())
            self.assertIn("args=127.0.0.1", direct_output.getvalue())
            self.assertIn("commandlet=hostscanner", selector_output.getvalue())
            self.assertIn("args=127.0.0.1", selector_output.getvalue())

    def test_job_show_numeric_serial_prefix_falls_back_after_missing_local_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            with runner.db.connect() as conn:
                conn.execute("UPDATE jobs SET serial = ? WHERE id = ?", ("41864964abcdef", job_id))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job 41864964")

            self.assertIn("serial=41864964", output.getvalue())
            self.assertIn("commandlet=hostscanner", output.getvalue())

    def test_event_job_selector_accepts_durable_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            serial = runner.db.job_serial(job_id)
            assert serial is not None
            runner.db.publish("job.requested", {"job_id": job_id, "job_serial": serial}, "runner")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"event job={serial}")

            self.assertIn(f"#{job_id}", output.getvalue())
            self.assertIn(f"serial={serial}", output.getvalue())

    def test_dispatch_steps_lists_historical_steps_by_default(self):
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
                dispatch_repl_line(runner, "step")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+hostscanner\s+1\s+0\s+")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "step --all")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+hostscanner\s+1\s+0\s+")

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
                dispatch_repl_line(runner, "pipeline")
            self.assertIn("failed/stale", output.getvalue())

    def test_job_lists_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
            text = output.getvalue()
            self.assertIn("ART", text)
            self.assertIn("COMMAND", text)
            self.assertNotIn("COMMANDLET", text)
            self.assertRegex(text, r"\n1\s+active/running\s+")
            self.assertIn("hostscanner 127.0.0.1", text)

    def test_jobs_all_marks_active_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("active", 123, "running")
            runner.db.record_job("old", 456, "finished")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")
            text = output.getvalue()
            self.assertRegex(text, r"\n1\s+active/running\s+")
            self.assertRegex(text, r"\n2\s+completed/finished\s+")

    def test_job_list_styles_active_row_and_status_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display/style.table.active_row", "green")
            runner.registry.varstore.set("display/style.table.active_column", "bold white")
            runner.db.record_job("active", 123, "running")
            runner.db.record_job("old", 456, "finished")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job")
            text = output.getvalue()
            self.assertIn("\x1b[32m1", text)
            self.assertIn("\x1b[1;37mactive/running", text)
            self.assertIn("completed/finished", text)
            completed_row = next(line for line in text.splitlines() if "completed/finished" in line)
            self.assertNotIn("\x1b[", completed_row)

    def test_job_listing_fits_terminal_width(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job(
                "network/portscanner host=192.0.2.10 ports=1-65535 arguments='-Pn -sT -4'",
                123,
                "running",
            )
            output = io.StringIO()
            with (
                patch("bywaf.runtime_display.shutil.get_terminal_size", return_value=os.terminal_size((72, 24))),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "job --all")
            lines = [line for line in output.getvalue().splitlines() if line]
            self.assertTrue(lines)
            self.assertTrue(all(len(line) <= 72 for line in lines), output.getvalue())

    def test_runtime_views_accept_sort_selector_and_reject_sort_flag(self):
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
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job sort=started")
                dispatch_repl_line(runner, "job sort=-started")
                dispatch_repl_line(runner, "pipeline sort=events")
                dispatch_repl_line(runner, "step sort=started")
                dispatch_repl_line(runner, "pipeline --sort=events")

            text = output.getvalue()
            self.assertIn("sorted by started ascending (use sort=-started to sort descending)", text)
            self.assertIn("sorted by started descending (use sort=started to sort ascending)", text)
            self.assertIn("sorted by events ascending (use sort=-events to sort descending)", text)
            self.assertIn("sorted by started ascending (use sort=-started to sort descending)", text)
            self.assertIn("error: pipeline uses selector syntax; use sort=<key>, not --sort=events", text)

    def test_runtime_view_filters_share_event_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_job = runner.db.record_job("portscanner host=192.0.2.10", 123, "finished")
            second_job = runner.db.record_job("portscanner host=192.0.2.20", 123, "finished")
            for job_id, pipeline_id, run_id, host in (
                (first_job, "pipe-1", "run-1", "192.0.2.10"),
                (second_job, "pipe-2", "run-2", "192.0.2.20"),
            ):
                runner.db.record_command_run_vars(
                    job_id=job_id,
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                    commandlet="portscanner",
                    values={},
                )
                runner.db.publish(
                    "port.open",
                    {"host": host, "port": 80, "protocol": "tcp"},
                    "portscanner",
                    pipeline_id=pipeline_id,
                    command_run_id=run_id,
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job host=192.0.2.20")
                dispatch_repl_line(runner, "pipeline host=192.0.2.20")
                dispatch_repl_line(runner, "step host=192.0.2.20")

            text = output.getvalue()
            self.assertIn("portscanner host=192.0.2.20", text)
            self.assertIn("PIPELINE", text)
            self.assertIn("STEP", text)
            self.assertIn("2", text)
            self.assertNotIn("portscanner host=192.0.2.10", text)

    def test_db_new_resets_repl_framework_request_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "old.sqlite3"))
            for index in range(5):
                runner.db.publish("noise", {"index": index}, "test")
            state = ShellState(framework_request_after_id=runner.db.latest_event_id())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"db new file={Path(tmp, 'new.sqlite3')}", state)
                runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
                dispatch_repl_line(runner, "job --all", state)

            text = output.getvalue()
            self.assertIn("created db=", text)
            self.assertIn("hostscanner", text)

    def test_job_listing_keeps_state_short_when_long_active_format_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.listing.active-format", "long")
            runner.db.record_job("active", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "job --all")
            self.assertNotIn("active since ", output.getvalue())
            self.assertRegex(output.getvalue(), r"\n1\s+active/running\s+")

    def test_pipeline_lists_by_default(self):
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
                dispatch_repl_line(runner, "pipeline")
            text = output.getvalue()
            self.assertIn("ART", text)
            self.assertRegex(text, rf"\n1\s+active/running\s+{job_id}\s+1\s+0\s+0\s+")

    def test_pipeline_list_lists_historical_pipelines_by_default(self):
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
                dispatch_repl_line(runner, "pipeline")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+1\s+0\s+0\s+")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pipeline --all")
            self.assertRegex(output.getvalue(), r"\n1\s+completed/finished\s+1\s+1\s+0\s+0\s+")

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

    def test_pause_resume_stop_commands_accept_step_selector(self):
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
                runner.execute("pause step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume --listonly step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("resume step=run-1")
                process_framework_requests(runner, ShellState())
            self.assertIn(f"soft pause requested for job {job_id}", output.getvalue())
            self.assertIn("run.pause.requested step=run-1", output.getvalue())
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "running")

    def test_signal_records_plugin_scoped_live_control_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("signal step=run-1 prune targets=192.168.1.0/24 reason=user-request")
                process_framework_requests(runner, ShellState())
            signal_event = runner.db.events_for_topic("runtime.signal.requested")[0]
            self.assertEqual(signal_event.command_run_id, "run-1")
            self.assertEqual(signal_event.payload["target_type"], "run")
            self.assertEqual(signal_event.payload["action"], "prune")
            self.assertEqual(signal_event.payload["args"]["targets"], "192.168.1.0/24")
            self.assertIn("signal requested for step=run-1 action=prune mode=soft", output.getvalue())

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
