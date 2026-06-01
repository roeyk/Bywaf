"""Tests for app dispatch behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import unittest

from bywaf.app import (
    build_parser,
    format_event,
    command_from_remainder,
    parse_load_spec,
)
from bywaf.cli_trust import plugin_trust_policy_from_args
from bywaf.event import Event



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
