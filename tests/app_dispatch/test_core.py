"""Tests for app dispatch behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    build_parser,
    database_argument_is_explicit,
    format_event,
    command_from_remainder,
    main,
    parse_load_spec,
    startup_database_path,
)
from bywaf.db import EventStore
from bywaf.cli_trust import plugin_trust_policy_from_args
from bywaf.event import Event
from bywaf.keyring import KeyRecord



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

    def test_database_argument_detection(self):
        self.assertFalse(database_argument_is_explicit(["repl"]))
        self.assertTrue(database_argument_is_explicit(["--database", "client.sqlite3", "repl"]))
        self.assertTrue(database_argument_is_explicit(["--database=client.sqlite3", "repl"]))

    def test_startup_uses_persisted_ad_hoc_database_without_explicit_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                database = Path(".bywaf/db/clean.sqlite3")
                EventStore(database)
                Path(".bywaf").mkdir(exist_ok=True)
                Path(".bywaf/active-database.json").write_text(
                    '{"database": ".bywaf/db/clean.sqlite3"}\n',
                    encoding="utf-8",
                )

                self.assertEqual(
                    startup_database_path(None, ".bywaf/bywaf.sqlite3", explicit_database=False),
                    database,
                )
                self.assertEqual(
                    startup_database_path(None, "manual.sqlite3", explicit_database=True),
                    Path("manual.sqlite3"),
                )
            finally:
                os.chdir(cwd)

    def test_build_parser_accepts_builtin_commands(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["plugins"]).subcommand, "plugins")
        graph_args = parser.parse_args(["plugins", "graph", "--json"])
        self.assertEqual(graph_args.subcommand, "plugins")
        self.assertEqual(graph_args.action, "graph")
        self.assertTrue(graph_args.json)
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

    def test_build_parser_accepts_setup_and_quiet(self):
        parser = build_parser()
        args = parser.parse_args(["--setup", "--quiet"])
        self.assertTrue(args.setup)
        self.assertTrue(args.quiet)

    def test_setup_creates_user_config_default_project_and_audit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["--setup"]), 0)

                config = Path(tmp, ".bywaf", "config.toml")
                project = Path(tmp, ".bywaf", "projects", "default")
                database = project / "bywaf.sqlite3"
                self.assertTrue(config.exists())
                self.assertTrue((project / "config.toml").exists())
                self.assertTrue((project / "history.bywaf").exists())
                self.assertTrue(database.exists())
                text = output.getvalue()
                self.assertIn("Bywaf configuration created", text)
                self.assertIn("Default project created", text)

                events = EventStore(database).events_for_topic("setup.completed")
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].payload["project"], "default")

    def test_quiet_setup_suppresses_summary_but_creates_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["--setup", "--quiet"]), 0)
                self.assertEqual(output.getvalue(), "")
                self.assertTrue(Path(tmp, ".bywaf", "config.toml").exists())

    def test_interactive_setup_keyboard_interrupt_cancels_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=KeyboardInterrupt),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("setup cancelled", output.getvalue())
                self.assertFalse(Path(tmp, ".bywaf", "projects", "default", "bywaf.sqlite3").exists())

    def test_interactive_setup_eof_cancels_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=EOFError),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("setup cancelled", output.getvalue())
                self.assertFalse(Path(tmp, ".bywaf", "config.toml").exists())

    def test_interactive_setup_accepts_project_name_and_declines_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-a", "n", "n"]),
                ):
                    self.assertEqual(main(["--setup"]), 0)

                project = Path(tmp, ".bywaf", "projects", "client-a")
                self.assertTrue(project.exists())
                self.assertIn("Use `bywaf project=client-a`", output.getvalue())
                events = EventStore(project / "bywaf.sqlite3").events_for_topic("setup.completed")
                self.assertFalse(events[-1].payload["encrypted"])
                self.assertEqual(events[-1].payload["generated_keys"], [])

    def test_interactive_setup_can_request_encrypted_project_database(self):
        calls: list[tuple[Path, str | None]] = []
        published: list[dict[str, object]] = []
        outer = self

        class FakeStore:
            def __init__(self, path: Path, *, passphrase: str | None = None):
                calls.append((path, passphrase))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            def publish(self, topic: str, payload: dict[str, object], source: str):
                outer.assertEqual(topic, "setup.completed")
                outer.assertEqual(source, "framework")
                published.append(payload)

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                with (
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-sec", "y", "n"]),
                    patch("bywaf.setup.sqlcipher_available", return_value=True),
                    patch("bywaf.setup.getpass.getpass", side_effect=["secret-passphrase", "secret-passphrase"]),
                    patch("bywaf.setup.EventStore", FakeStore),
                ):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(main(["--setup"]), 0)

        self.assertEqual(calls[-1][1], "secret-passphrase")
        self.assertEqual(published[-1]["project"], "client-sec")
        self.assertTrue(published[-1]["encrypted"])
        self.assertIn("encrypted SQLCipher", output.getvalue())

    def test_interactive_setup_can_generate_signing_keys(self):
        generated_names: list[str] = []

        def fake_generate_key(name: str, passphrase: str, *, scope: str = "user"):
            generated_names.append(name)
            self.assertEqual(passphrase, "key-passphrase")
            self.assertEqual(scope, "user")
            return KeyRecord(
                name=name,
                scope=scope,
                algorithm="ed25519",
                fingerprint=f"SHA256:{name}",
                public_path=Path("/tmp/keys/public") / f"{name}.pub.pem",
                private_path=Path("/tmp/keys/private") / f"{name}.pem",
            )

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp, "BYWAF_KEY_ROOT": str(Path(tmp, "keys"))}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-keys", "n", "y"]),
                    patch("bywaf.setup.getpass.getpass", side_effect=["key-passphrase", "key-passphrase"]),
                    patch("bywaf.setup.generate_key", side_effect=fake_generate_key),
                ):
                    self.assertEqual(main(["--setup"]), 0)

                self.assertEqual(generated_names, ["bundle-signing"])
                self.assertIn("Generated signing keys: bundle-signing", output.getvalue())
                events = EventStore(Path(tmp, ".bywaf", "projects", "client-keys", "bywaf.sqlite3")).events_for_topic(
                    "setup.keys_configured"
                )
                self.assertEqual(len(events), 1)
                self.assertEqual(
                    [record["name"] for record in events[0].payload["generated_keys"]],
                    ["bundle-signing"],
                )

    def test_interactive_setup_key_generation_failure_does_not_publish_setup_event(self):
        def fail_generate_key(name: str, passphrase: str, *, scope: str = "user"):
            del name, passphrase, scope
            raise RuntimeError("key backend unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp, "BYWAF_KEY_ROOT": str(Path(tmp, "keys"))}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-fail", "n", "y"]),
                    patch("bywaf.setup.getpass.getpass", side_effect=["key-passphrase", "key-passphrase"]),
                    patch("bywaf.setup.generate_key", side_effect=fail_generate_key),
                ):
                    self.assertEqual(main(["--setup"]), 1)

                self.assertIn("error: key backend unavailable", output.getvalue())
                database = Path(tmp, ".bywaf", "projects", "client-fail", "bywaf.sqlite3")
                self.assertFalse(database.exists())

    def test_interactive_setup_refuses_to_encrypt_existing_project_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, ".bywaf", "projects", "default")
            project.mkdir(parents=True)
            (project / "bywaf.sqlite3").write_text("existing", encoding="utf-8")
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["", "y"]),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("cannot enable encryption during setup because project database already exists", output.getvalue())

    def test_interactive_repl_startup_shows_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=True),
                    patch("sys.stdout.isatty", return_value=True),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["repl"]), 0)
                self.assertIn("No Bywaf configuration found.", output.getvalue())
                self.assertIn("Run `bywaf --setup` to create one, or continue with defaults.", output.getvalue())

    def test_quiet_repl_startup_suppresses_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=True),
                    patch("sys.stdout.isatty", return_value=True),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["--quiet", "repl"]), 0)
                self.assertNotIn("No Bywaf configuration found.", output.getvalue())

    def test_non_interactive_repl_startup_suppresses_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=False),
                    patch("sys.stdout.isatty", return_value=False),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["repl"]), 0)
                self.assertNotIn("No Bywaf configuration found.", output.getvalue())

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
                {"name": "example.test", "host": "203.0.113.10"},
                "name.resolved example.test -> 203.0.113.10",
            ),
            (
                "name.resolved",
                {"name": "legacy.test", "addresses": ["203.0.113.10", "203.0.113.11"]},
                "name.resolved legacy.test -> 203.0.113.10, 203.0.113.11",
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


if __name__ == "__main__":
    unittest.main()
