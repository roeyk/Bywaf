"""Tests for app os and help behavior.

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
    dispatch_repl_line,
    make_runner,
)



class AppDispatchTests(unittest.TestCase):
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
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["/usr/bin/less", "-R", "--", str(path)])
            self.assertFalse(run.call_args.kwargs["check"])
            self.assertEqual(run.call_args.kwargs["env"]["LESSSECURE"], "1")

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
            self.assertEqual(argv[2], "--")
            self.assertFalse(Path(argv[3]).exists())
            self.assertEqual(run.call_args.kwargs["env"]["LESSSECURE"], "1")

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
            self.assertIn("error: unknown command or commandlet", output.getvalue())

    def test_dispatch_help_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "?")
            self.assertIn("plugins", output.getvalue())
            self.assertIn("cmds", output.getvalue())
            self.assertIn("script", output.getvalue())

    def test_manifest_commandlet_help_uses_key_value_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help traceroute")
            text = output.getvalue()
            self.assertIn("binary=BINARY", text)
            self.assertIn("maxhops=MAXHOPS", text)
            self.assertIn("timeout=TIMEOUT", text)
            self.assertIn("--silent", text)
            self.assertNotIn("--binary", text)
            self.assertNotIn("--maxhops", text)
            self.assertNotIn("--timeout", text)

    def test_commandlet_alias_help_uses_canonical_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help web_fingerprint")
            text = output.getvalue()
            self.assertIn("usage: webfin", text)
            self.assertIn("--timeout", text)
            self.assertIn("--user-agent", text)

    def test_cmds_lists_web_fingerprint_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "cmds")
            text = output.getvalue()
            self.assertIn("ALIASES", text)
            self.assertIn("webfin", text)
            self.assertIn("web_fingerprint", text)

    def test_web_fingerprint_alias_dispatch_keeps_canonical_audit_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("web_fingerprint")
            argument_events = runner.db.events_for_topic("command.run.arguments")
            self.assertEqual(argument_events[-1].payload["commandlet"], "webfin")
            started_events = runner.db.events_for_topic("command.run.started")
            self.assertEqual(started_events[-1].payload["commandlet"], "webfin")
            job_events = runner.db.events_for_topic("job.requested")
            self.assertEqual(job_events[-1].payload["command"], "web_fingerprint")

    def test_signal_help_and_missing_args_show_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "signal")
                dispatch_repl_line(runner, "help signal")
                dispatch_repl_line(runner, "signal --help")
            text = output.getvalue()
            self.assertIn("usage: signal <job=id|step=id|serial=id> <action>", text)
            self.assertIn("actions: prune, mute, unmute", text)
            self.assertIn("examples:", text)
            self.assertNotIn("signal requires target and action", text)

    def test_inventory_help_shows_common_scope_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "help hosts")
                dispatch_repl_line(runner, "help wafs")
                dispatch_repl_line(runner, "help ports")
            text = output.getvalue()
            self.assertIn("--last", text)
            self.assertIn("--new", text)
            self.assertIn("job=<id>", text)
            self.assertIn("pipeline=<id>", text)
            self.assertIn("step=<id>", text)
            self.assertIn("all=true", text)

    def test_wafs_inventory_renders_waf_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("waf_detect https://example.test/", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="waf-pipeline",
                command_run_id="waf-step",
                commandlet="waf_detect",
                values={},
            )
            runner.db.publish(
                "web.waf.detected",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "vendor": "Cloudflare",
                    "product": "Cloudflare WAF",
                    "confidence": "high",
                    "evidence": "server header",
                },
                "waf_detect",
                pipeline_id="waf-pipeline",
                command_run_id="waf-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "wafs")

            text = output.getvalue()
            self.assertIn("WAFs: project inventory", text)
            self.assertIn("Cloudflare", text)
            self.assertIn("https://example.test/", text)

    def test_web_inventory_includes_fingerprint_technology(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("webfin https://example.test/", 123, "finished")
            runner.db.record_command_run_vars(
                job_id=1,
                pipeline_id="web-pipeline",
                command_run_id="webfin-step",
                commandlet="webfin",
                values={},
            )
            runner.db.publish(
                "web.fingerprint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "status": 200,
                    "server": "nginx",
                    "technologies": ["nginx", "jquery"],
                    "observations": [{"severity": "low", "message": "missing header"}],
                    "interesting": True,
                },
                "webfin",
                pipeline_id="web-pipeline",
                command_run_id="webfin-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "web")

            text = output.getvalue()
            self.assertIn("Web: project inventory", text)
            self.assertIn("https://example.test/", text)
            self.assertIn("nginx", text)
            self.assertIn("jquery", text)

    def test_schemas_view_lists_versions_and_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "schemas topic=web. sort=topic")

            text = output.getvalue()
            self.assertIn("Schemas: all registered schemas topic=web.", text)
            self.assertIn("sorted by topic ascending", text)
            self.assertIn("web.fingerprint", text)
            self.assertIn("web.waf.detect", text)
            self.assertIn("VER", text)
            self.assertIn("wafs", text)

    def test_schemas_detail_shows_plugin_owned_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "schemas owner=plugin topic=web. detail=true")

            text = output.getvalue()
            self.assertIn("Schemas: owner=plugin topic=web.", text)
            self.assertIn("Schema detail: web.fingerprint", text)
            self.assertIn("owner: plugin", text)
            self.assertIn("FIELD", text)
            self.assertIn("technologies", text)
            self.assertIn("observations", text)
            self.assertIn("webfin", text)

    def test_wafs_new_shows_latest_new_waf_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "web.waf.detected",
                {"url": "https://old.example.test/", "host": "old.example.test", "vendor": "Akamai"},
                "waf_detect",
                pipeline_id="old-pipeline",
                command_run_id="old-step",
            )
            runner.db.publish(
                "web.waf.detected",
                {"url": "https://new.example.test/", "host": "new.example.test", "vendor": "Cloudflare"},
                "waf_detect",
                pipeline_id="new-pipeline",
                command_run_id="new-step",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "wafs --new")

            text = output.getvalue()
            self.assertIn("WAFs: new since prior inventory", text)
            self.assertIn("https://new.example.test/", text)
            self.assertNotIn("https://old.example.test/", text)

    def test_dispatch_help_colors_commands_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("display.help.color", "always")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "?")
            self.assertIn("\x1b[32mplugins", output.getvalue())


if __name__ == "__main__":
    unittest.main()
