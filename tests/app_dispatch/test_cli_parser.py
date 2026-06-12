"""Tests for top-level CLI parsing and startup path selection.

Coverage focus: app dispatch cli parser regression behavior.
"""

from pathlib import Path
import os
import tempfile
import unittest
import contextlib
import io

from bywaf.app import (
    build_parser,
    command_from_remainder,
    database_argument_is_explicit,
    parse_load_spec,
    startup_database_path,
)
from bywaf.cli_trust import trust_policy_from_args
from bywaf.db import EventStore


class CliParserTests(unittest.TestCase):
    """Groups regression coverage for top-level CLI parsing and startup path selection."""
    def test_build_parser_accepts_exec(self):
        """Protect build parser accepts exec behavior from regressions."""
        parser = build_parser()
        args = parser.parse_args(["exec", "echo", "hello"])
        self.assertEqual(args.subcommand, "exec")
        self.assertEqual(args.command, ["echo", "hello"])

    def test_route_direct_commandlet_argv(self):
        """Protect route direct commandlet argv behavior from regressions."""
        from bywaf.app import route_direct_commandlet_argv

        self.assertEqual(route_direct_commandlet_argv(["hostscanner", "127.0.0.1"]), ["cmd", "hostscanner", "127.0.0.1"])
        self.assertEqual(route_direct_commandlet_argv(["exec", "echo", "hello"]), ["exec", "echo", "hello"])

    def test_build_parser_accepts_cmds_page(self):
        """Protect build parser accepts cmds page behavior from regressions."""
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

        policy = trust_policy_from_args(args)

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


if __name__ == "__main__":
    unittest.main()
