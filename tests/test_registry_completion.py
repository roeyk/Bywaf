"""Tests for registry completion behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import unittest
import os
import importlib
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import ModuleType

from bywaf.completion import (
    COMPLETION_SELECT_KEY_VAR,
    COMPLETION_WASD_SELECTION_VAR,
    Completer,
    PromptToolkitCompleter,
    cancel_completion_menu,
    common_completion_prefix,
    completion_results,
    completion_select_key,
    completion_select_key_display,
    completion_wasd_selection_enabled,
    configure_readline_delimiters,
    display_label,
    should_print_completion_menu,
    tokens_after_last_pipe,
)
from bywaf.db import EventStore
from bywaf.registry import (
    PluginRegistry,
    PluginTrustError,
    PluginTrustPolicy,
    canonical_manifest_bytes,
    load_package_manifest,
    load_plugin,
    parse_package_plugin_config,
    parse_plugin_config,
    parse_plugin_manifest,
    plugin_manifest_digest,
)
from bywaf.secret_input import open_secret_assignment_name
from bywaf.specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec, TriggerSpec
from bywaf.tools.plugin_manifest import manifest_from_plugins


class RegistryCompletionTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry.discover()

    def test_discovers_bundled_plugins(self):
        self.assertIn("hostscanner", self.registry.names())
        self.assertIn("dns_lookup", self.registry.names())
        self.assertIn("ldap_probe", self.registry.names())
        self.assertIn("portscanner", self.registry.names())
        self.assertIn("shodan_lookup", self.registry.names())
        self.assertIn("smb_probe", self.registry.names())
        self.assertIn("snmp_get", self.registry.names())
        self.assertIn("ssh_probe", self.registry.names())
        self.assertIn("eyewitness", self.registry.names())
        self.assertIn("http_headers", self.registry.names())
        self.assertIn("http_probe", self.registry.names())
        self.assertIn("nikto", self.registry.names())
        self.assertIn("webfin", self.registry.names())
        self.assertIn("wifi_scan", self.registry.names())
        self.assertIn("finding_dedupe", self.registry.names())
        self.assertIn("finding_report", self.registry.names())
        self.assertIn("yara_scan", self.registry.names())
        self.assertIn("db", self.registry.names())
        self.assertIn("job", self.registry.names())
        self.assertIn("pipeline", self.registry.names())
        self.assertIn("end", self.registry.names())
        self.assertIn("kill", self.registry.names())
        self.assertIn("cancel", self.registry.names())
        self.assertIn("pause", self.registry.names())
        self.assertIn("resume", self.registry.names())
        self.assertIn("stop", self.registry.names())
        self.assertIn("signal", self.registry.names())
        self.assertIn("audit", self.registry.names())
        self.assertIn("bundle", self.registry.names())
        self.assertIn("key", self.registry.names())
        self.assertIn("note", self.registry.names())
        self.assertIn("name", self.registry.names())
        self.assertIn("artifact", self.registry.names())
        self.assertIn("watchdog", self.registry.names())

    def test_bundled_plugins_are_loaded_from_config_list(self):
        entries = parse_package_plugin_config("bywaf.plugins", "plugins.toml")
        self.assertEqual(
            entries,
            [
                "discovery.hostscanner",
                "analysis.finding_dedupe",
                "analysis.finding_report",
                "analysis.yara_scan",
                "identity.ldap_probe",
                "identity.smb_probe",
                "network.portscanner",
                "network.snmp_get",
                "network.ssh_probe",
                "recon.dns_lookup",
                "recon.shodan_lookup",
                "http.http_headers",
                "http.eyewitness",
                "http.http_probe",
                "http.nikto",
                "http.webfin",
                "wireless.wifi_scan",
                "runtime.job",
                "runtime.pipeline",
                "runtime.control",
                "runtime.audit",
                "runtime.bundle",
                "runtime.key",
                "runtime.note",
                "runtime.name",
                "runtime.artifact",
                "runtime.watchdog",
                "storage.db",
                "os.ls",
                "os.cat",
                "os.less",
            ],
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertIsNotNone(load_package_manifest("bywaf.plugins", entry))

    def test_bundled_sidecar_manifest_traits(self):
        manifest = load_package_manifest("bywaf.plugins", "http.nikto")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlets, frozenset({"nikto"}))
        self.assertFalse(manifest.library_backed)
        self.assertTrue(manifest.process_wrapped)
        self.assertFalse(manifest.native)

    def test_bundled_watchdog_manifest_is_service(self):
        manifest = load_package_manifest("bywaf.plugins", "runtime.watchdog")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlets, frozenset({"watchdog"}))
        self.assertTrue(manifest.service)
        self.assertTrue(manifest.native)

    def test_canonical_manifest_bytes_ignore_order_and_signature_block(self):
        first = {
            "plugin": {"roles": ["beta", "alpha"], "native": True},
            "trusted_keys": ["key-b", "key-a"],
            "commandlets": [
                {"name": "two", "capabilities": ["b", "a"]},
                {"name": "one", "secret_options": ["token", "password"]},
            ],
            "triggers": [
                {
                    "name": "network",
                    "topic": "plugin.capability.used",
                    "action_command": "watchdog --session-service",
                    "exclude_commandlets": ["watchdog", "audit"],
                    "payload_equals": {"b": "2", "a": "1"},
                }
            ],
            "bywaf_signature": {"digest": "old", "signature": "old"},
        }
        second = {
            "bywaf_signature": {"digest": "new", "signature": "new"},
            "triggers": [
                {
                    "payload_equals": {"a": "1", "b": "2"},
                    "exclude_commandlets": ["audit", "watchdog"],
                    "action_command": "watchdog --session-service",
                    "topic": "plugin.capability.used",
                    "name": "network",
                }
            ],
            "commandlets": [
                {"secret_options": ["password", "token"], "name": "one"},
                {"capabilities": ["a", "b"], "name": "two"},
            ],
            "trusted_keys": ["key-a", "key-b"],
            "plugin": {"native": True, "roles": ["alpha", "beta"]},
        }

        self.assertEqual(canonical_manifest_bytes(first), canonical_manifest_bytes(second))
        self.assertEqual(plugin_manifest_digest(first), plugin_manifest_digest(second))

    def test_canonical_manifest_digest_changes_when_values_change(self):
        first = {"commandlets": [{"name": "example", "capabilities": ["network.connect"]}]}
        second = {"commandlets": [{"name": "example", "capabilities": ["filesystem.read"]}]}

        self.assertNotEqual(plugin_manifest_digest(first), plugin_manifest_digest(second))

    def test_bundled_watchdog_provides_network_trigger(self):
        triggers = {trigger.name: trigger for trigger in self.registry.triggers}
        trigger = triggers["network-access-starts-watchdog"]
        self.assertEqual(trigger.topic, "plugin.capability.used")
        self.assertEqual(trigger.capability, "network.connect")
        self.assertEqual(trigger.action_command, "watchdog --session-service")
        self.assertEqual(trigger.action_mode, "service")
        self.assertTrue(trigger.active_job)

    def test_bundled_sidecar_manifest_declares_secret_options(self):
        manifest = load_package_manifest("bywaf.plugins", "network.ssh_probe")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlet_secret_options["ssh_probe"], ("password",))

    def test_registry_tracks_provider_groups(self):
        self.assertEqual(self.registry.grouped_names()["analysis"], ["finding_dedupe", "finding_report", "yara_scan"])
        self.assertEqual(self.registry.grouped_names()["identity"], ["ldap_probe", "smb_probe"])
        self.assertEqual(self.registry.grouped_names()["network"], ["portscanner", "snmp_get", "ssh_probe"])
        self.assertIn("os", self.registry.provider_names())
        self.assertEqual(self.registry.grouped_names()["os"], ["cat", "less", "ls"])
        self.assertEqual(self.registry.grouped_names()["recon"], ["dns_lookup", "shodan_lookup"])
        self.assertEqual(
            self.registry.grouped_names()["runtime"],
            [
                "artifact",
                "audit",
                "bundle",
                "cancel",
                "end",
                "job",
                "key",
                "kill",
                "name",
                "note",
                "pause",
                "pipeline",
                "resume",
                "search",
                "signal",
                "stop",
                "watchdog",
            ],
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
        self.assertIn("targets=", completer.candidates("var "))
        self.assertNotIn("hostscanner.targets=", completer.candidates("var "))
        self.assertEqual(completer.candidates("var global.pro"), ["global.proxy="])

    def test_vars_completion_supports_secret_flag(self):
        self.registry.varstore.set("ssh_probe.password", "")
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("var --s"), ["--secret"])
        self.assertIn("ssh_probe.", completer.candidates("var --secret "))
        self.assertEqual(completer.candidates("var --secret ssh_probe.pass"), ["ssh_probe.password="])
        self.assertNotIn("--secret", completer.candidates("var --secret "))

    def test_secret_input_block_opens_only_for_var_secret_assignments(self):
        self.assertEqual(open_secret_assignment_name("var --secret ssh_probe.password="), "ssh_probe.password")
        self.assertEqual(open_secret_assignment_name("var ssh_probe.password --secret="), "ssh_probe.password")
        self.assertIsNone(open_secret_assignment_name("vars --secret ssh_probe.password="))
        self.assertIsNone(open_secret_assignment_name("var password="))

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
            self.assertEqual(completer.candidates("portscanner --from-run "), ["1"])
            self.assertEqual(completer.candidates("portscanner --from-pipeline "), ["1"])
            self.assertIn("serial=run-1", completer.candidates("event serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("event serial="))
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
            self.assertEqual(completer.candidates("event run="), ["run=1"])
            self.assertEqual(completer.candidates("event pipeline="), ["pipeline=1"])
            self.assertIn("serial=run-1", completer.candidates("event serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("event serial="))
            self.assertEqual(completer.candidates("event job="), [f"job={job_id}"])
            self.assertIn("topic=host.found", completer.candidates("event topic="))

    def test_runtime_completion_metadata_includes_artifact_counts(self):
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
            db.publish(
                "artifact.attached",
                {"artifact_id": "artifact-1", "job_id": job_id},
                "framework",
                pipeline_id="pipeline-1",
                command_run_id="run-1",
            )
            completer = Completer(self.registry, db)
            self.assertIn("artifacts=1", completer.completion_meta("run=1", "event run=", "run="))
            self.assertIn("artifacts=1", completer.completion_meta("pipeline=1", "event pipeline=", "pipeline="))
            self.assertIn("artifacts=1", completer.completion_meta(f"job={job_id}", "event job=", "job="))

    def test_tokens_after_last_pipe(self):
        self.assertEqual(tokens_after_last_pipe(["hostscanner", "x", "|", "por"]), ["por"])

    def test_completes_plugin_options(self):
        completer = Completer(self.registry)
        self.assertIn("ports=", completer.candidates("portscanner por"))
        self.assertIn("--from-run", completer.candidates("portscanner --from"))
        http_options = completer.candidates("http_headers --")
        self.assertIn("--help", http_options)
        self.assertIn("port=", completer.candidates("http_headers po"))
        self.assertIn("ssl=", completer.candidates("http_headers ss"))
        self.assertIn("timeout=", completer.candidates("http_headers ti"))
        probe_options = completer.candidates("http_probe --")
        self.assertIn("--silent", probe_options)
        self.assertIn("cookie-file=", completer.candidates("http_probe coo"))
        self.assertIn("firefox-profile=", completer.candidates("http_probe fir"))
        self.assertIn("method=", completer.candidates("http_probe me"))

    def test_artifact_completion_prefers_actions_first(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("artifact "), ["attach", "list", "remove", "replace", "save", "search", "verify"])
        self.assertEqual(completer.candidates("artifact a"), ["attach"])
        self.assertIn("file=", completer.candidates("artifact attach "))
        self.assertIn("file=", completer.candidates("artifact replace "))
        self.assertIn("dir=", completer.candidates("artifact save "))
        self.assertIn("note=", completer.candidates("artifact search "))
        self.assertIn("--regexp", completer.candidates("search "))
        self.assertIn("filename=", completer.candidates("search "))
        self.assertIn("content=", completer.candidates("search "))

    def test_prompt_toolkit_completer_hides_repeated_key_prefix_in_display(self):
        Document = importlib.import_module("prompt_toolkit.document").Document

        completer = PromptToolkitCompleter(Completer(self.registry))
        completions = list(completer.get_completions(Document("event topic=h"), None))
        display_texts = [completion.display_text for completion in completions]
        self.assertIn("host.found", display_texts)
        self.assertNotIn("topic=host.found", display_texts)

    def test_prompt_toolkit_selection_key_is_configurable(self):
        completer = Completer(self.registry)
        self.assertEqual(completion_select_key(completer), "c-space")
        self.assertEqual(completion_select_key_display(completer), "Ctrl-Space")
        self.registry.varstore.set(COMPLETION_SELECT_KEY_VAR, "c-j")
        self.assertEqual(completion_select_key(completer), "c-j")
        self.assertEqual(completion_select_key_display(completer), "Ctrl-J")
        self.assertFalse(completion_wasd_selection_enabled(completer))
        self.registry.varstore.set(COMPLETION_WASD_SELECTION_VAR, "true")
        self.assertTrue(completion_wasd_selection_enabled(completer))

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
            self.assertEqual(completer.candidates("pipeline attach "), ["1"])
            self.assertIn("portscanner", completer.candidates("pipeline attach pipe-1 por"))
            self.assertIn("run=1", completer.candidates("pipeline attach pipe-1 portscanner run="))
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
                "--from-pipeline",
                "--from-run",
                "--from-topic",
                "--help",
                "--listen",
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
        self.assertEqual(completer.candidates("load --f"), ["--force"])

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

    def test_event_completes_topics_and_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("custom.topic", {"ok": True}, "test")
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            candidates = completer.candidates("event ")
            self.assertIn("custom.topic", candidates)
            self.assertIn("job=1", candidates)

    def test_events_completes_tail_selectors(self):
        completer = Completer(self.registry)
        self.assertIn("--tail", completer.candidates("events "))
        self.assertNotIn("tail", completer.candidates("events "))
        self.assertIn("last=", completer.candidates("events "))

    def test_job_completes_actions_and_job_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            self.assertIn("cancel", completer.candidates("job "))
            self.assertIn("end", completer.candidates("job e"))
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
            self.assertIn("end", completer.candidates("pipeline e"))
            self.assertIn("kill", completer.candidates("pipeline k"))
            self.assertEqual(completer.candidates("pipeline show "), ["1"])
            self.assertEqual(completer.candidates("end job="), ["job=1"])
            self.assertEqual(completer.candidates("kill job="), ["job=1"])
            self.assertEqual(completer.candidates("kill pipeline="), ["pipeline=1"])
            self.assertIn("serial=run-1", completer.candidates("signal serial="))
            self.assertIn("serial=pipe-1", completer.candidates("signal serial="))
            self.assertEqual(completer.candidates("cancel pipeline="), ["pipeline=1"])

    def test_project_completes_actions_and_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_root = Path(tmp, ".bywaf", "projects")
            (project_root / "client-a").mkdir(parents=True)
            (project_root / "client-b").mkdir()
            completer = Completer(self.registry)
            with patch("pathlib.Path.home", return_value=Path(tmp)):
                self.assertEqual(completer.candidates("project "), ["info", "list", "new", "use"])
                self.assertEqual(completer.candidates("project i"), ["info"])
                self.assertEqual(completer.candidates("project new "), ["--encrypt", "name="])
                self.assertEqual(completer.candidates("project use "), ["--force", "name="])
                self.assertEqual(completer.candidates("project use name=client-"), ["name=client-a", "name=client-b"])
                self.assertEqual(completer.candidates("project use c"), ["client-a", "client-b"])
                self.assertEqual(completer.candidates("project use --f"), ["--force"])

    def test_builtin_commands_do_not_fall_back_to_root_completion(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("plugins "), [])
        self.assertEqual(completer.candidates("info "), [])
        self.assertEqual(completer.candidates("triggers "), [])
        self.assertEqual(completer.candidates("exit "), [])
        self.assertEqual(completer.candidates("quit "), [])
        self.assertEqual(completer.candidates("q "), [])
        self.assertEqual(completer.candidates("cmds "), ["--page"])
        self.assertEqual(completer.candidates("cmds --"), ["--page"])
        self.assertEqual(completer.candidates("jobs "), ["--all", "--page"])
        self.assertEqual(completer.candidates("pipelines "), ["--page"])
        self.assertEqual(completer.candidates("runs "), ["--all"])
        self.assertIn("plugins", completer.candidates("help plu"))
        self.assertIn("project", completer.candidates("? pro"))

    def test_cancel_completion_menu_dismisses_active_popup(self):
        class Buffer:
            cancelled = False

            def cancel_completion(self):
                self.cancelled = True

        class Event:
            current_buffer = Buffer()

        event = Event()
        cancel_completion_menu(event)
        self.assertTrue(event.current_buffer.cancelled)

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

    def test_parse_toml_plugin_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')
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
            (plugin_dir / "defaults.toml").write_text("[defaults]\nanswer = 42\n")
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "native = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')
            registry = PluginRegistry.from_config(root, config, forced=True)
            self.assertIn("example", registry.names())
            self.assertEqual(registry.varstore.get("example.answer"), "42")

    def test_filesystem_plugin_requires_force_without_verified_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(PluginTrustError, "refusing external plugin"):
                PluginRegistry.from_config(root, config)

    def test_filesystem_plugin_loads_with_unsigned_developer_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
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
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            registry = PluginRegistry.from_config(
                root,
                config,
                trust_policy=PluginTrustPolicy(allow_unsigned_plugins=True, allow_unsigned_plugin_manifests=True),
            )

            self.assertIn("example", registry.names())

    def test_loads_legacy_filesystem_plugin_json_defaults(self):
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
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "native = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.yaml")
            config.write_text("default_plugins:\n  - scanners/example\n")
            registry = PluginRegistry.from_config(root, config, forced=True)
            self.assertEqual(registry.varstore.get("example.answer"), "42")

    def test_filesystem_manifest_is_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "class Extra:\n"
                "    spec = CommandSpec('extra', 'extra plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugins():\n"
                "    return (Example(), Extra())\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "library_backed = true\n"
                "process_wrapped = true\n"
                "service = false\n"
                'roles = ["command-provider"]\n\n'
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            registry = PluginRegistry.from_config(root, config, forced=True)

            self.assertIn("example", registry.names())
            self.assertNotIn("extra", registry.names())
            manifest = parse_plugin_manifest(plugin_dir / "bywaf.plugin.toml")
            self.assertTrue(manifest.library_backed)
            self.assertTrue(manifest.process_wrapped)
            self.assertFalse(manifest.native)

    def test_filesystem_manifest_rejects_missing_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text("[[commandlets]]\nname = \"missing\"\n")
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "missing commandlets"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_filesystem_plugins_require_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(FileNotFoundError, "bywaf.plugin.toml"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_filesystem_manifest_rejects_conflicting_native_trait(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "bywaf.plugin.toml")
            manifest.write_text(
                "[plugin]\n"
                "native = true\n"
                "library_backed = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
            )
            with self.assertRaisesRegex(ValueError, "native=true conflicts"):
                parse_plugin_manifest(manifest)

    def test_filesystem_manifest_rejects_non_string_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "bywaf.plugin.toml")
            manifest.write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = [123]\n"
            )

            with self.assertRaisesRegex(ValueError, "capabilities entry 1 must be a string"):
                parse_plugin_manifest(manifest)

    def test_filesystem_manifest_rejects_string_boolean(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "bywaf.plugin.toml")
            manifest.write_text(
                "[plugin]\n"
                'service = "false"\n\n'
                "[[commandlets]]\n"
                'name = "example"\n'
            )

            with self.assertRaisesRegex(ValueError, "plugin.service must be true or false"):
                parse_plugin_manifest(manifest)

    def test_filesystem_manifest_rejects_non_string_trigger_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "bywaf.plugin.toml")
            manifest.write_text(
                "[[commandlets]]\n"
                'name = "example"\n\n'
                "[[triggers]]\n"
                'name = "example-trigger"\n'
                'topic = "example.event"\n'
                'action_command = "example"\n'
                "capability = 123\n"
            )

            with self.assertRaisesRegex(ValueError, "capability must be a string"):
                parse_plugin_manifest(manifest)

    def test_filesystem_manifest_rejects_non_string_payload_equals_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp, "bywaf.plugin.toml")
            manifest.write_text(
                "[[commandlets]]\n"
                'name = "example"\n\n'
                "[[triggers]]\n"
                'name = "example-trigger"\n'
                'topic = "example.event"\n'
                'action_command = "example"\n'
                "payload_equals = { count = 3 }\n"
            )

            with self.assertRaisesRegex(ValueError, "payload_equals values must be strings"):
                parse_plugin_manifest(manifest)

    def test_filesystem_manifest_rejects_capability_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', capabilities=('network.connect',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "capabilities mismatch"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_filesystem_manifest_rejects_secret_option_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec, OptionSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', options=(OptionSpec('password', 'password', secret=True),))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
                "secret_options = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "secret_options mismatch"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_bundled_watchdog_manifest_declares_trigger_metadata(self):
        manifest = load_package_manifest("bywaf.plugins", "runtime.watchdog")
        self.assertIsNotNone(manifest)
        assert manifest is not None

        trigger = {item.name: item for item in manifest.triggers}["network-access-starts-watchdog"]

        self.assertEqual(trigger.topic, "plugin.capability.used")
        self.assertEqual(trigger.action_command, "watchdog --session-service")
        self.assertEqual(trigger.capability, "network.connect")
        self.assertTrue(trigger.active_job)
        self.assertEqual(trigger.exclude_commandlets, ("watchdog",))

    def test_filesystem_manifest_rejects_trigger_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            write_trigger_plugin(plugin_dir)
            write_trigger_manifest(plugin_dir, action_command="example --wrong")
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "trigger mismatch"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_filesystem_manifest_rejects_missing_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            write_trigger_manifest(plugin_dir)
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "declares missing triggers"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_filesystem_manifest_rejects_undeclared_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            write_trigger_plugin(plugin_dir)
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "exposes undeclared triggers"):
                PluginRegistry.from_config(root, config, forced=True)

    def test_plugin_manifest_tool_infers_secret_options(self):
        class Example:
            spec = CommandSpec(
                "example",
                "example plugin",
                options=(OptionSpec("password", "password", secret=True),),
                capabilities=("framework.secret.resolve",),
            )

            def run(self, context, args, input_events):
                yield {"ok": True}

        text = manifest_from_plugins((Example(),))
        self.assertIn('name = "example"', text)
        self.assertIn('  "framework.secret.resolve",', text)
        self.assertIn('secret_options = ["password"]', text)

    def test_plugin_manifest_tool_generates_trigger_specs(self):
        class Example:
            spec = CommandSpec("example", "example plugin")

            def run(self, context, args, input_events):
                yield {"ok": True}

        trigger = TriggerSpec(
            name="example-trigger",
            topic="example.event",
            action_command="example",
            description="ON example.event DO example",
            action_mode="background",
            payload_equals=(("kind", "demo"),),
        )

        text = manifest_from_plugins((Example(),), (trigger,))

        self.assertIn("[[triggers]]", text)
        self.assertIn('name = "example-trigger"', text)
        self.assertIn('topic = "example.event"', text)
        self.assertIn('action_command = "example"', text)
        self.assertIn('payload_equals = { kind = "demo" }', text)


def write_trigger_plugin(plugin_dir: Path) -> None:
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec, TriggerSpec\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
        "def plugin():\n"
        "    return Example()\n"
        "def triggers():\n"
        "    return (TriggerSpec(\n"
        "        name='example-trigger',\n"
        "        topic='example.event',\n"
        "        action_command='example',\n"
        "        description='ON example.event DO example',\n"
        "        action_mode='background',\n"
        "        payload_equals=(('kind', 'demo'),),\n"
        "    ),)\n"
    )


def write_trigger_manifest(plugin_dir: Path, *, action_command: str = "example") -> None:
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = []\n\n"
        "[[triggers]]\n"
        'name = "example-trigger"\n'
        'topic = "example.event"\n'
        f'action_command = "{action_command}"\n'
        'description = "ON example.event DO example"\n'
        'action_mode = "background"\n'
        'payload_equals = { kind = "demo" }\n'
    )


if __name__ == "__main__":
    unittest.main()
