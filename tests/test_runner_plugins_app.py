from pathlib import Path
import contextlib
import io
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    build_parser,
    dispatch_repl_line,
    format_event,
    friendly_error,
    main,
    make_runner,
    command_from_remainder,
    process_framework_requests,
    render_prompt,
    record_command_history,
    resolve_resource_path,
    repl,
    run_script,
    save_history,
    set_prompt_pattern,
    parse_save_spec,
    shutdown_runner,
    load_history,
    script_commands,
    strip_inline_comment,
)
from bywaf.db import EventStore, Subscription
from bywaf.db import database_appears_encrypted, sqlcipher_available
from bywaf.events import Event
from bywaf.nmap_backend import NmapPort, NmapScanError, NmapUnavailableError
from bywaf.plugins.http.http_headers import HttpHeaders
from bywaf.plugins.discovery.hostscanner import HostScanner
from bywaf.plugins.discovery.hostscanner import expand_targets
from bywaf.plugins.os.less import page_file
from bywaf.plugins.network.portscanner import PortScanner
from bywaf.plugins.storage.db import encrypt_active_database
from bywaf.plugin import CommandContext
from bywaf.runner import parse_invocation, parse_pipeline


class RunnerPluginAppTests(unittest.TestCase):
    def test_parse_invocation_uses_first_token_as_name(self):
        invocation = parse_invocation("hostscanner 127.0.0.1")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])

    def test_parse_pipeline(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1 | portscanner --ports 80 &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertFalse(pipeline.commands[0].background)
        self.assertTrue(pipeline.commands[1].background)

    def test_parse_stage_background_pipeline(self):
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 & | portscanner &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.background for command in pipeline.commands], [True, True])
        self.assertEqual(pipeline.commands[0].args, ["192.168.0.1-2"])

    def test_parse_attached_background_markers(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1& | portscanner&")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertEqual(pipeline.commands[0].args, ["127.0.0.1"])
        self.assertEqual([command.background for command in pipeline.commands], [True, True])

    def test_parse_framework_context_selectors(self):
        invocation = parse_invocation(
            "portscanner --from-run host-run --from-pipeline pipe --from-topic host.found --ports 80"
        )
        self.assertEqual(invocation.from_run, "host-run")
        self.assertEqual(invocation.from_pipeline, "pipe")
        self.assertEqual(invocation.from_topic, "host.found")
        self.assertEqual(invocation.args, ["--ports", "80"])

    def test_parse_save_spec_accepts_encrypt_before_resource(self):
        encrypt, resource = parse_save_spec("--encrypt db=client.sqlite3")
        self.assertTrue(encrypt)
        self.assertEqual(resource, "db=client.sqlite3")

    def test_db_commandlet_reports_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("db status")
            text = output.getvalue()
            self.assertIn("mode=plaintext", text)
            self.assertIn("events=1", text)

    def test_db_new_file_creates_and_switches_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertEqual(runner.db.table_counts()["events"], 0)
            self.assertEqual(EventStore(first).table_counts()["events"], 1)

    def test_db_new_refuses_existing_file_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with self.assertRaisesRegex(ValueError, "already exists"):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, first)
            self.assertEqual(EventStore(second).table_counts()["events"], 1)

    def test_db_new_force_backs_up_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --force --file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertEqual(runner.db.table_counts()["events"], 0)
            backups = list(Path(tmp).glob("second.sqlite3.bak-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(EventStore(backups[0]).table_counts()["events"], 1)

    def test_db_new_default_path_uses_bywaf_db_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                runner = make_runner(Path("current.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("db new")
                self.assertEqual(runner.db.path.parent, Path(".bywaf/db"))
                self.assertTrue(runner.db.path.name.startswith("bywaf-"))
            finally:
                os.chdir(cwd)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_commandlet_encrypt_decrypts_and_rekeys_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "db.sqlite3")
            runner = make_runner(path)
            runner.db.publish("topic", {"value": 1}, "test")
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                runner.execute("db encrypt")
            self.assertTrue(runner.db.encrypted)
            self.assertTrue(database_appears_encrypted(path))
            self.assertEqual(runner.db.events_for_topic("topic")[0].payload["value"], 1)
            with patch("getpass.getpass", side_effect=["newsecret", "newsecret"]):
                runner.execute("db rekey")
            self.assertEqual(EventStore(path, passphrase="newsecret").table_counts()["events"], 1)
            with patch("builtins.input", return_value="YES"):
                runner.execute("db decrypt")
            self.assertFalse(runner.db.encrypted)
            self.assertFalse(database_appears_encrypted(path))
            self.assertEqual(runner.db.events_for_topic("topic")[0].payload["value"], 1)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_new_encrypt_creates_encrypted_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"db new --encrypt --file={second}")
            self.assertTrue(runner.db.encrypted)
            self.assertTrue(database_appears_encrypted(second))

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_new_uses_encryption_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.registry.varstore.set("db.encryption", "sqlcipher")
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"db new --file={second}")
            self.assertTrue(runner.db.encrypted)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_encrypt_rejects_background_conversion(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(
                EventStore(Path(tmp, "db.sqlite3")),
                source="db",
                metadata={"background": True},
            )
            with self.assertRaisesRegex(ValueError, "foreground"):
                encrypt_active_database(context)

    def test_parse_empty_invocation_fails(self):
        with self.assertRaises(ValueError):
            parse_invocation("")

    def test_run_hostscanner_publishes_host_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    events = runner.execute("hostscanner 127.0.0.1")
            self.assertEqual(events[0].topic, "host.found")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            self.assertEqual(events[0].payload["scanner"], "nmap")
            discover.assert_called_once_with("127.0.0.1", "-sn")
            self.assertIn("hostscanner <", output.getvalue())
            self.assertIn(">: discovered host 127.0.0.1", output.getvalue())

    def test_hostscanner_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="hostscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
            contextlib.redirect_stdout(output),
        ):
            events = list(HostScanner().run(context, ["-s", "127.0.0.1"], []))
        self.assertEqual(events[0]["host"], "127.0.0.1")
        self.assertEqual(output.getvalue(), "")

    def test_hostscanner_expands_range_before_nmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-2")
            discover.assert_called_once_with("192.168.0.1 192.168.0.2", "-sn")

    def test_expand_targets_enforces_limit(self):
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            expand_targets(["192.168.0.1-3"], 2)

    def test_pipeline_scans_open_local_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[
                        NmapPort(
                            host="127.0.0.1",
                            port=8080,
                            protocol="tcp",
                            state="open",
                            service="http",
                        )
                    ],
                ),
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    events = runner.execute("hostscanner 127.0.0.1 | portscanner --ports 8080")
                self.assertEqual(events[-1].topic, "port.open")
                self.assertEqual(events[-1].payload["port"], 8080)
                self.assertEqual(events[-1].payload["scanner"], "nmap")
                self.assertIsNotNone(events[0].pipeline_id)
                self.assertEqual(events[-1].parent_command_run_id, events[0].command_run_id)
                self.assertIn("portscanner <", output.getvalue())
                self.assertIn(">: discovered port 8080/tcp on host 127.0.0.1", output.getvalue())

    def test_commandlet_can_use_events_from_prior_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="host-run",
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner --from-run host-run --ports 80")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            self.assertEqual(scan.call_args.args[0], ["127.0.0.1"])

    def test_portscanner_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="portscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ),
            contextlib.redirect_stdout(output),
        ):
            events = list(PortScanner().run(context, ["-s", "127.0.0.1"], []))
        self.assertEqual(events[0]["port"], 80)
        self.assertEqual(output.getvalue(), "")

    def test_portscanner_listen_scopes_to_upstream_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "192.0.2.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            db.publish(
                "host.found",
                {"host": "198.51.100.1"},
                "hostscanner",
                pipeline_id="pipe-2",
                command_run_id="upstream-1",
            )
            context = CommandContext(
                db,
                source="portscanner",
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                },
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[
                    NmapPort(
                        host="192.0.2.1",
                        port=443,
                        protocol="tcp",
                        state="open",
                    )
                ],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))
            self.assertEqual(events[0]["host"], "192.0.2.1")
            scan.assert_called_once()
            self.assertEqual(scan.call_args.args[0], ["192.0.2.1"])

    def test_portscanner_listen_requires_upstream_pipeline_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(EventStore(Path(tmp, "db.sqlite3")), source="portscanner")
            with self.assertRaisesRegex(ValueError, "must be used after an upstream"):
                list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))

    def test_background_portscanner_auto_listens_to_upstream_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "203.0.113.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            context = CommandContext(
                db,
                source="portscanner",
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                    "background": True,
                },
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("203.0.113.1", 80, "tcp", "open")],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen-timeout", "0.01"], []))
            self.assertEqual(events[0]["host"], "203.0.113.1")

    def test_background_command_records_job_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            with patch("bywaf.nmap_backend.load_backend", return_value=("fake", FakeNmapModule())):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 &")
            self.assertEqual(events[0].topic, "job.requested")
            db = EventStore(db_path)
            deadline = time.time() + 5
            found = []
            while time.time() < deadline:
                found = db.fetch(Subscription(("host.found",)))
                if found:
                    break
                time.sleep(0.1)
            self.assertEqual(found[0].payload["host"], "127.0.0.1")
            topics = db.topics()
            self.assertIn("job.claimed", topics)
            self.assertIn("job.started", topics)
            self.assertIn("job.finished", topics)

    def test_background_job_preserves_attached_stage_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.runner.mp.Process") as process_cls:
                process = process_cls.return_value
                process.pid = 123
                runner.execute("hostscanner 127.0.0.1& | portscanner&")
            self.assertEqual(
                process_cls.call_args.kwargs["args"][3],
                "hostscanner 127.0.0.1& | portscanner&",
            )
            self.assertIsNone(process_cls.call_args.kwargs["args"][1])

    def test_build_parser_accepts_run(self):
        parser = build_parser()
        args = parser.parse_args(["run", "hostscanner", "127.0.0.1"])
        self.assertEqual(args.subcommand, "run")
        self.assertEqual(args.command, ["hostscanner", "127.0.0.1"])
        self.assertEqual(args.database, ".bywaf/bywaf.sqlite3")

    def test_build_parser_accepts_builtin_commands(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["plugins"]).subcommand, "plugins")
        self.assertEqual(parser.parse_args(["cmds"]).subcommand, "cmds")
        self.assertEqual(parser.parse_args(["history"]).subcommand, "history")

    def test_build_parser_rejects_direct_os_commandlets(self):
        parser = build_parser()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["ls"])

    def test_command_from_remainder_quotes_tokens(self):
        self.assertEqual(command_from_remainder(["cat", "file name.txt"]), "cat 'file name.txt'")

    def test_command_from_remainder_preserves_single_quoted_pipeline(self):
        self.assertEqual(
            command_from_remainder(["ls bywaf/plugins/os | cat README.md"]),
            "ls bywaf/plugins/os | cat README.md",
        )

    def test_format_event(self):
        event = Event.new("topic", {"x": 1}, "test")
        self.assertIn("topic", format_event(event))

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

    def test_dispatch_plugins_lists_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "plugins")
            self.assertIn("discovery", output.getvalue())
            self.assertIn("os", output.getvalue())

    def test_dispatch_cmds_lists_commandlets_grouped_by_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "cmds")
            self.assertIn("os\n", output.getvalue())
            self.assertIn("  ls\n", output.getvalue())
            self.assertIn("  cat\n", output.getvalue())

    def test_dispatch_list_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "list")
            self.assertIn("error: unknown command or commandlet: list", output.getvalue())

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
            with (
                patch("bywaf.plugins.os.less.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.plugins.os.less.sys.stdin.isatty", return_value=True),
                patch("bywaf.plugins.os.less.sys.stdout.isatty", return_value=True),
                patch("bywaf.plugins.os.less.subprocess.run") as run,
            ):
                page_file(path)
            run.assert_called_once_with(["/usr/bin/less", str(path)], check=False)

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

    def test_dispatch_runs_lists_command_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "runs")
            self.assertIn("r pipeline=p source=hostscanner events=1", output.getvalue())

    def test_jobs_alias_runs_job_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "jobs")
            self.assertIn("#1 pid=123 status=running hostscanner 127.0.0.1", output.getvalue())

    def test_job_cancel_records_soft_cancellation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("portscanner --listen", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"job cancel {job_id}")
            self.assertIn(f"cancel requested for job {job_id}", output.getvalue())
            self.assertTrue(runner.db.cancellation_requested(job_id=job_id))
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "cancelling")

    def test_job_kill_sends_term_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job kill {job_id}")
            self.assertEqual(kill.call_args.args[0], 99999)
            self.assertEqual(kill.call_args.args[1].name, "SIGTERM")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "terminated")

    def test_job_kill_force_sends_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("sleep", 99999, "running")
            with patch("bywaf.plugins.runtime.job.os.kill") as kill:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"job kill --force {job_id}")
            self.assertEqual(kill.call_args.args[1].name, "SIGKILL")
            job = runner.db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "killed")

    def test_dispatch_show_run_and_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            run_output = io.StringIO()
            pipe_output = io.StringIO()
            with contextlib.redirect_stdout(run_output):
                dispatch_repl_line(runner, "show run=r")
            with contextlib.redirect_stdout(pipe_output):
                dispatch_repl_line(runner, "show pipeline=p")
            self.assertIn("127.0.0.1", run_output.getvalue())
            self.assertIn("127.0.0.1", pipe_output.getvalue())

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
                dispatch_repl_line(runner, "help vars")
            self.assertIn("Usage:   vars [name=value]", output.getvalue())

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
        self.assertEqual(strip_inline_comment("vars name='a # b' # later").strip(), "vars name='a # b'")

    def test_record_command_history_writes_script_friendly_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            session_history = []
            entry = record_command_history("ls bywaf", path, session_history)
            text = path.read_text()
            self.assertRegex(text, r"^ls bywaf  # \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}( [A-Z]+)?\n$")
            self.assertEqual(script_commands(path)[0][1], "ls bywaf")
            self.assertEqual(session_history, [entry])

    def test_record_command_history_uses_configured_timestamp_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("plugins", path, timestamp_format="%Y/%m/%d")
            self.assertRegex(path.read_text(), r"^plugins  # \d{4}/\d{2}/\d{2}\n$")

    def test_dispatch_history_prints_session_history_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp, ".bywaf", "history.bywaf")
            record_command_history("old-command", history_path)
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(history_path=history_path, session_history=["plugins  # now"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "history", state)
            self.assertIn("plugins  # ", output.getvalue())
            self.assertNotIn("old-command", output.getvalue())

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
                    dispatch_repl_line(runner, "save history=session.bywaf", state)
                state.session_history = []
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "load history=session.bywaf", state)
                self.assertEqual(state.session_history, ["cmds  # now"])
            finally:
                os.chdir(cwd)

    def test_load_script_executes_commands_sequentially(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("# comment\nvars test.value=abc\nvars\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                run_script(runner, script)
            self.assertEqual(runner.registry.varstore.get("test.value"), "abc")
            self.assertIn("test.value=abc", output.getvalue())

    def test_dispatch_load_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("vars loaded.value=yes\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"load script={script}")
            self.assertEqual(runner.registry.varstore.get("loaded.value"), "yes")

    def test_save_and_load_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            config = Path(tmp, "vars.json")
            dispatch_repl_line(runner, "vars test.value=before")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"save config={config}")
            dispatch_repl_line(runner, "vars test.value=after")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"load config={config}")
            self.assertEqual(runner.registry.varstore.get("test.value"), "before")

    def test_save_and_load_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("custom.topic", {"ok": True}, "test")
            saved = Path(tmp, "saved.sqlite3")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"save db={saved}")
            other = make_runner(Path(tmp, "other.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(other, f"load db={saved}")
            self.assertEqual(other.db.path, saved)
            self.assertEqual(other.db.topics(), ["custom.topic"])

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
                dispatch_repl_line(runner, "vars")
            self.assertIn("portscanner.ports=", output.getvalue())

    def test_dispatch_vars_assignment_sets_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            dispatch_repl_line(runner, "vars custom.value=abc")
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
                dispatch_repl_line(runner, "show host.found")
            self.assertIn("host.found", topics.getvalue())
            self.assertIn("127.0.0.1", shown.getvalue())

    def test_dispatch_show_job_prints_matching_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "running")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"show job={job_id}")
            self.assertIn("hostscanner 127.0.0.1", output.getvalue())

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
            self.assertEqual(event.payload["old_prompt"], "bywaf> ")
            self.assertEqual(event.payload["new_prompt"], "new> ")

    def test_framework_request_updates_prompt_and_records_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": "requested> "}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "requested> ")
            updated = runner.db.events_for_topic("shell.prompt.updated")[0]
            self.assertEqual(updated.payload["request_event_id"], request.id)

    def test_framework_request_denies_invalid_prompt_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            request = runner.db.publish("shell.prompt.requested", {"prompt": ""}, "test")
            process_framework_requests(runner, state)
            self.assertEqual(state.prompt_pattern, "bywaf> ")
            denied = runner.db.events_for_topic("framework.request.denied")[0]
            self.assertEqual(denied.payload["request_event_id"], request.id)

    def test_framework_request_is_processed_once_per_shell_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.db.publish("shell.prompt.requested", {"prompt": "once> "}, "test")
            process_framework_requests(runner, state)
            process_framework_requests(runner, state)
            self.assertEqual(len(runner.db.events_for_topic("shell.prompt.updated")), 1)

    def test_render_prompt_replaces_time_placeholder(self):
        self.assertNotIn("%T", render_prompt("%T> "))

    def test_make_runner_loads_external_plugin_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "external"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class External:\n"
                "    spec = CommandSpec('external', 'external plugin', emits=('external.event',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'external': True}\n"
                "def plugin():\n"
                "    return External()\n"
            )
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/external\n")
            runner = make_runner(Path(tmp, "db.sqlite3"), plugin_root=root, plugin_config=config)
            self.assertIn("external", runner.registry.names())

    def test_friendly_error_strips_keyerror_quotes(self):
        self.assertEqual(friendly_error(KeyError("unknown commandlet: x")), "unknown commandlet: x")

    def test_http_headers_targets_from_arg(self):
        targets = HttpHeaders().targets("example.test", None, False, [])
        self.assertEqual(targets, [("example.test", 80, False)])

    def test_http_headers_targets_from_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = HttpHeaders().targets(None, None, False, [event])
        self.assertEqual(targets, [("127.0.0.1", 443, True)])


if __name__ == "__main__":
    unittest.main()


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
