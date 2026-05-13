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
    format_event,
    main,
    make_runner,
    command_from_remainder,
    process_framework_requests,
    repl,
    shutdown_runner,
)
from bywaf.events import Event
class AppDispatchTests(unittest.TestCase):
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
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.app.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.app.sys.stdin.isatty", return_value=True),
                patch("bywaf.app.sys.stdout.isatty", return_value=True),
                patch("bywaf.app.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, f"less {path}")
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
                process_framework_requests(runner, ShellState())
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
