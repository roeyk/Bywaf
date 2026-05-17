import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import ModuleType

from bywaf.completion import (
    Completer,
    common_completion_prefix,
    completion_results,
    configure_readline_delimiters,
    display_label,
    should_print_completion_menu,
    tokens_after_last_pipe,
)
from bywaf.db import EventStore
from bywaf.plugin import ArgumentSpec, CommandSpec, CompletionSpec
from bywaf.registry import PluginRegistry, load_plugin, parse_package_plugin_config, parse_plugin_config


class RegistryCompletionTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry.discover()

    def test_discovers_bundled_plugins(self):
        self.assertIn("hostscanner", self.registry.names())
        self.assertIn("portscanner", self.registry.names())
        self.assertIn("http_headers", self.registry.names())
        self.assertIn("http_probe", self.registry.names())
        self.assertIn("db", self.registry.names())
        self.assertIn("job", self.registry.names())
        self.assertIn("pipeline", self.registry.names())
        self.assertIn("kill", self.registry.names())
        self.assertIn("cancel", self.registry.names())
        self.assertIn("pause", self.registry.names())
        self.assertIn("resume", self.registry.names())
        self.assertIn("stop", self.registry.names())
        self.assertIn("signal", self.registry.names())
        self.assertIn("audit", self.registry.names())
        self.assertIn("note", self.registry.names())
        self.assertIn("name", self.registry.names())
        self.assertIn("artifact", self.registry.names())

    def test_bundled_plugins_are_loaded_from_config_list(self):
        self.assertEqual(
            parse_package_plugin_config("bywaf.plugins", "plugins.json"),
            [
                "discovery.hostscanner",
                "network.portscanner",
                "http.http_headers",
                "http.http_probe",
                "runtime.job",
                "runtime.pipeline",
                "runtime.control",
                "runtime.audit",
                "runtime.note",
                "runtime.name",
                "runtime.artifact",
                "storage.db",
                "os.ls",
                "os.cat",
                "os.less",
            ],
        )

    def test_registry_tracks_provider_groups(self):
        self.assertIn("os", self.registry.provider_names())
        self.assertEqual(self.registry.grouped_names()["os"], ["cat", "less", "ls"])
        self.assertEqual(
            self.registry.grouped_names()["runtime"],
            ["artifact", "audit", "cancel", "job", "kill", "name", "note", "pause", "pipeline", "resume", "signal", "stop"],
        )
        self.assertEqual(self.registry.grouped_names()["storage"], ["db"])

    def test_loads_package_defaults_into_varstore(self):
        self.assertEqual(self.registry.varstore.get("portscanner.ports"), "")

    def test_get_unknown_raises_clear_key_error(self):
        with self.assertRaisesRegex(KeyError, "unknown commandlet"):
            self.registry.get("missing")

    def test_completes_command_names(self):
        completer = Completer(self.registry)
        self.assertIn("hostscanner", completer.candidates("host"))
        self.assertIn("history", completer.candidates("hist"))
        self.assertIn("ls", completer.candidates("l"))
        self.assertIn("plugins", completer.candidates("plu"))
        self.assertNotIn("repl", completer.candidates("re"))
        self.assertEqual(
            completer.candidates("hostscanner 127.0.0.1& | por"),
            ["portscanner"],
        )

    def test_prompt_has_no_argument_completion(self):
        self.assertEqual(Completer(self.registry).candidates("prompt "), [])

    def test_run_completes_commandlet_pipeline_names(self):
        self.assertEqual(Completer(self.registry).candidates("run host"), ["hostscanner"])

    def test_use_completes_contexts(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("use glo"), ["global"])
        self.assertEqual(completer.candidates("use host"), ["hostscanner"])

    def test_vars_completion_prefers_active_context_scope(self):
        self.registry.varstore.set("hostscanner.targets", "127.0.0.1")
        self.registry.varstore.set("global.proxy", "http://127.0.0.1:8080")
        completer = Completer(self.registry, active_context="hostscanner")
        self.assertIn("targets=", completer.candidates("vars "))
        self.assertNotIn("hostscanner.targets=", completer.candidates("vars "))
        self.assertEqual(completer.candidates("vars global.pro"), ["global.proxy="])

    def test_completes_history_time_window_selectors(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("history s"), ["since="])
        self.assertEqual(completer.candidates("history u"), ["until="])

    def test_completes_file_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "file.txt").write_text("x")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("cat fi"), ["file.txt"])
                self.assertEqual(completer.candidates("less fi"), ["file.txt"])
                self.assertEqual(completer.candidates("ls fi"), ["file.txt"])
                self.assertIn("file.txt", completer.candidates("ls "))
            finally:
                os.chdir(cwd)

    def test_at_file_completion_preserves_operator_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "targets.txt").write_text("127.0.0.1\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("hostscanner @tar"), ["@targets.txt"])
                self.assertEqual(completer.candidates("hostscanner @@tar"), ["@@targets.txt"])
                self.assertEqual(completer.candidates("hostscanner @lines:tar"), ["@lines:targets.txt"])
                self.assertEqual(completer.candidates("hostscanner @raw:tar"), ["@raw:targets.txt"])
            finally:
                os.chdir(cwd)

    def test_file_command_completion_is_declared_by_plugin_specs(self):
        for name in ("cat", "less", "ls"):
            commandlet = self.registry.get(name)
            self.assertEqual(commandlet.spec.arguments[0].completion.kind, "file" if name in ("cat", "less") else "path")

    def test_completes_from_custom_plugin_completer(self):
        class Custom:
            spec = CommandSpec("custom", "custom completion")

            def run(self, context, args, input_events):
                return ()

            def complete(self, context, args, prefix):
                return ["alpha", "beta"]

        self.registry.plugins["custom"] = Custom()
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("custom a"), ["alpha"])

    def test_completion_spec_can_complete_loaded_plugins(self):
        class UsesPlugin:
            spec = CommandSpec(
                "uses_plugin",
                "plugin completion",
                arguments=(ArgumentSpec("plugin", completion=CompletionSpec("plugin")),),
            )

            def run(self, context, args, input_events):
                return ()

        self.registry.plugins["uses_plugin"] = UsesPlugin()
        completer = Completer(self.registry)
        self.assertIn("hostscanner", completer.candidates("uses_plugin host"))

    def test_completes_framework_context_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipeline-1",
                command_run_id="run-1",
            )
            completer = Completer(self.registry, db)
            self.assertEqual(completer.candidates("portscanner --from-run "), ["run-1"])
            self.assertEqual(completer.candidates("portscanner --from-pipeline "), ["pipeline-1"])
            self.assertIn("host.found", completer.candidates("portscanner --from-topic "))

    def test_show_completes_selector_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipeline-1",
                command_run_id="run-1",
            )
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            self.assertEqual(completer.candidates("show run="), ["run=run-1"])
            self.assertEqual(completer.candidates("show pipeline="), ["pipeline=pipeline-1"])
            self.assertEqual(completer.candidates("show job="), [f"job={job_id}"])
            self.assertIn("topic=host.found", completer.candidates("show topic="))

    def test_tokens_after_last_pipe(self):
        self.assertEqual(tokens_after_last_pipe(["hostscanner", "x", "|", "por"]), ["por"])

    def test_completes_plugin_options(self):
        completer = Completer(self.registry)
        self.assertIn("--ports", completer.candidates("portscanner --p"))
        self.assertIn("--from-run", completer.candidates("portscanner --from"))
        http_options = completer.candidates("http_headers --")
        self.assertIn("--help", http_options)
        self.assertIn("--port", http_options)
        self.assertIn("--ssl", http_options)
        self.assertIn("--timeout", http_options)
        probe_options = completer.candidates("http_probe --")
        self.assertIn("--cookie-file", probe_options)
        self.assertIn("--firefox-profile", probe_options)
        self.assertIn("--method", probe_options)

    def test_artifact_completion_prefers_actions_first(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("artifact "), ["attach", "list", "remove", "replace", "save", "verify"])
        self.assertEqual(completer.candidates("artifact a"), ["attach"])
        self.assertIn("file=", completer.candidates("artifact attach "))
        self.assertIn("file=", completer.candidates("artifact replace "))
        self.assertIn("dir=", completer.candidates("artifact save "))

    def test_control_completion_includes_run_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", command_run_id="run-1")
            completer = Completer(self.registry, db)
            self.assertIn("run=", completer.candidates("pause "))
            self.assertEqual(completer.candidates("pause run="), ["run=run-1"])
            self.assertIn("run=", completer.candidates("signal "))
            self.assertEqual(completer.candidates("signal run="), ["run=run-1"])
            self.assertIn("prune", completer.candidates("signal run=run-1 "))
            self.assertIn("targets=", completer.candidates("signal run=run-1 prune "))

    def test_pipeline_attach_completion_prefers_action_then_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="host-run-1",
            )
            completer = Completer(self.registry, db)
            self.assertIn("attach", completer.candidates("pipeline "))
            self.assertEqual(completer.candidates("pipeline attach "), ["pipe-1"])
            self.assertIn("portscanner", completer.candidates("pipeline attach pipe-1 por"))
            self.assertIn("run=host-run-1", completer.candidates("pipeline attach pipe-1 portscanner run="))
            self.assertEqual(
                completer.candidates("pipeline attach pipe-1 portscanner since="),
                ["since=beginning", "since=now"],
            )

    def test_does_not_complete_exact_option_to_itself(self):
        completer = Completer(self.registry)
        self.assertNotIn("--ports", completer.candidates("portscanner --ports"))

    def test_double_dash_only_lists_options(self):
        completer = Completer(self.registry)
        self.assertEqual(
            completer.candidates("portscanner --"),
            [
                "--arguments",
                "--except",
                "--from-pipeline",
                "--from-run",
                "--from-topic",
                "--help",
                "--listen",
                "--listen-interval",
                "--listen-timeout",
                "--ports",
                "--silent",
            ],
        )

    def test_option_completion_does_not_append_space(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.format_candidate("--ports"), "--ports")

    def test_completes_plugin_option_choices(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("http_headers --ssl "), ["false", "true"])

    def test_completes_plugin_option_default_value(self):
        completer = Completer(self.registry)
        self.assertIn("-sT", completer.candidates("portscanner --arguments "))

    def test_load_without_space_completes_command_name(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("loa"), ["load"])
        self.assertEqual(completer.candidates("load"), [])

    def test_load_plugin_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".bywaf", "plugins", "plugin_dir").mkdir(parents=True)
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("load plugin=plug"), ["plugin=plugin_dir/"])
            finally:
                os.chdir(cwd)

    def test_load_plugin_explicit_path_completes_local_filesystem(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "local_plugin").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("load plugin=./loc"), ["plugin=./local_plugin/"])
            finally:
                os.chdir(cwd)

    def test_load_resource_keywords_complete_from_prefix(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("load co"), ["config="])
        self.assertEqual(completer.candidates("load db"), ["db="])
        self.assertEqual(completer.candidates("load hi"), ["history="])
        self.assertEqual(completer.candidates("load pl"), ["plugin="])
        self.assertEqual(completer.candidates("load sc"), ["script="])

    def test_save_resource_keywords_complete_from_prefix(self):
        completer = Completer(self.registry)
        self.assertIn("save", completer.candidates("sav"))
        self.assertEqual(completer.candidates("save co"), ["config="])
        self.assertEqual(completer.candidates("save db"), ["db="])
        self.assertEqual(completer.candidates("save hi"), ["history="])

    def test_load_script_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "script.bywaf").write_text("ls\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("load script=scr"), ["script=script.bywaf"])
            finally:
                os.chdir(cwd)

    def test_load_history_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "history.bywaf").write_text("ls\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("load history=his"), ["history=history.bywaf"])
            finally:
                os.chdir(cwd)

    def test_load_raw_prefix_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "bywaf.sqlite3").write_text("")
            Path(tmp, "bywaf").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("load bywa"), ["bywaf.sqlite3", "bywaf/"])
            finally:
                os.chdir(cwd)

    def test_multiple_file_matches_complete_common_base_first(self):
        candidates = ["bywaf.sqlite3", "bywaf/"]
        self.assertEqual(common_completion_prefix("load byw", candidates), "bywaf")
        self.assertEqual(completion_results("load byw", candidates)[0], "bywaf")

    def test_key_value_file_matches_complete_common_base_first(self):
        candidates = ["plugin=bywaf.sqlite3", "plugin=bywaf/"]
        self.assertEqual(common_completion_prefix("load plugin=byw", candidates), "plugin=bywaf")
        self.assertEqual(completion_results("load plugin=byw", candidates)[0], "plugin=bywaf")

    def test_complete_returns_common_prefix_before_key_value_menu(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp, ".bywaf", "plugins")
            plugin_dir.mkdir(parents=True)
            Path(plugin_dir, "bywaf.sqlite3").write_text("")
            Path(plugin_dir, "bywaf").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                with patch("bywaf.completion.readline.get_line_buffer", return_value="load plugin=by"):
                    self.assertEqual(completer.complete("", 0), "plugin=bywaf")
            finally:
                os.chdir(cwd)

    def test_key_value_completion_display_strips_key_prefix(self):
        self.assertEqual(display_label("script=README.md"), "README.md")
        self.assertEqual(display_label("plugin=bywaf/"), "bywaf/")

    def test_key_value_completion_uses_custom_menu(self):
        self.assertTrue(
            should_print_completion_menu(
                "load script=",
                ["script=README.md", "script=tests/"],
            )
        )
        self.assertFalse(should_print_completion_menu("por", ["portscanner"]))

    def test_show_completes_topics_and_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("custom.topic", {"ok": True}, "test")
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            candidates = completer.candidates("show ")
            self.assertIn("custom.topic", candidates)
            self.assertIn("job=1", candidates)

    def test_job_completes_actions_and_job_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            self.assertIn("cancel", completer.candidates("job "))
            self.assertIn("kill", completer.candidates("job k"))
            self.assertEqual(completer.candidates("job show "), ["1"])
            self.assertEqual(completer.candidates("job cancel "), ["1"])

    def test_pipeline_and_control_complete_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            completer = Completer(self.registry, db)
            self.assertIn("kill", completer.candidates("pipeline k"))
            self.assertEqual(completer.candidates("pipeline show "), ["pipe-1"])
            self.assertEqual(completer.candidates("kill job="), ["job=1"])
            self.assertEqual(completer.candidates("kill pipeline="), ["pipeline=pipe-1"])
            self.assertEqual(completer.candidates("cancel pipeline="), ["pipeline=pipe-1"])

    def test_readline_delimiters_keep_hyphen_and_equals_in_completion_word(self):
        with (
            patch("bywaf.completion.readline.get_completer_delims", return_value=" \t\n-="),
            patch("bywaf.completion.readline.set_completer_delims") as set_delims,
        ):
            configure_readline_delimiters()
        set_delims.assert_called_once_with(" \t\n")

    def test_load_plugin_requires_factory(self):
        module = ModuleType("empty")
        with self.assertRaisesRegex(AttributeError, "does not define plugin"):
            load_plugin(module)

    def test_parse_simple_yaml_plugin_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/example\n")
            self.assertEqual(parse_plugin_config(config), ["scanners/example"])

    def test_loads_filesystem_plugin_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', emits=('example.event',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "defaults.json").write_text('{"answer": 42}')
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/example\n")
            registry = PluginRegistry.from_config(root, config)
            self.assertIn("example", registry.names())
            self.assertEqual(registry.varstore.get("example.answer"), "42")


if __name__ == "__main__":
    unittest.main()
