# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility.

Coverage focus: registry completion completion core regression behavior.
"""

from tests.registry_completion.support import *  # noqa: F403,F405


class RegistryCompletionCoreTests(unittest.TestCase):
    """Core completion behavior across commands, contexts, files, and secrets.

    These tests exercise `Completer.candidates()` directly because completion
    is a user-facing contract but does not require a full prompt-toolkit UI.
    """

    def setUp(self):
        """Create a fresh bundled registry for each completion scenario."""
        self.registry = PluginRegistry.discover()

    def test_completes_command_names(self):
        """Protect completes command names behavior from regressions."""
        completer = Completer(self.registry)
        # Command completion should include public commandlets and aliases, but
        # not internal implementation names such as the REPL provider itself.
        self.assertIn("hostscanner", completer.candidates("host"))
        self.assertIn("http/http_probe", completer.candidates("http/"))
        self.assertIn("history", completer.candidates("hist"))
        self.assertIn("ls", completer.candidates("l"))
        self.assertIn("plugins", completer.candidates("plu"))
        self.assertIn("web_fingerprint", completer.candidates("web_f"))
        self.assertNotIn("repl", completer.candidates("re"))
        self.assertEqual(
            completer.candidates("hostscanner 127.0.0.1& | por"),
            ["portscanner"],
        )

    def test_prompt_has_no_argument_completion(self):
        """Protect prompt has no argument completion behavior from regressions."""
        self.assertEqual(Completer(self.registry).candidates("prompt "), [])

    def test_exec_does_not_complete_commandlet_pipeline_names(self):
        """Protect exec does not complete commandlet pipeline names behavior from regressions."""
        self.assertEqual(Completer(self.registry).candidates("exec host"), [])

    def test_step_completes_step_ids(self):
        """Protect step completes step ids behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", command_run_id="run-1")
            completer = Completer(self.registry, db)
            self.assertIn("1", completer.candidates("step "))

    def test_use_completes_contexts(self):
        """Protect use completes contexts behavior from regressions."""
        completer = Completer(self.registry)
        top_level = completer.candidates("use ")
        self.assertIn("analysis/", top_level)
        self.assertIn("network/", top_level)
        self.assertNotIn("analysis/report", top_level)
        self.assertNotIn("analysis/report/report", top_level)
        self.assertEqual(
            completer.candidates("use analysis/"),
            [
                "analysis/finding",
                "analysis/finding/",
                "analysis/report",
                "analysis/technology_indicators",
                "analysis/yara_scan",
            ],
        )
        self.assertEqual(
            completer.candidates("use analysis/finding/"),
            [
                "analysis/finding/dedupe",
                "analysis/finding/report",
            ],
        )
        self.assertEqual(completer.candidates("use glo"), ["global"])
        self.assertEqual(completer.candidates("use host"), ["hosts", "hostscanner"])

    def test_vars_completion_prefers_active_context_scope(self):
        """Protect vars completion prefers active context scope behavior from regressions."""
        self.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1")
        self.registry.varstore.set("global.proxy", "http://127.0.0.1:8080")
        completer = Completer(self.registry, active_context="discovery/hostscanner")
        # In an active plugin context, local variable names are offered first;
        # fully qualified names remain available when the user types a prefix.
        self.assertIn("targets=", completer.candidates("set "))
        self.assertNotIn("discovery/hostscanner.targets=", completer.candidates("set "))
        self.assertEqual(completer.candidates("set global.pro"), ["global.proxy="])

    def test_vars_completion_supports_secret_flag(self):
        """Protect vars completion supports secret flag behavior from regressions."""
        self.registry.varstore.set("network/ssh_probe.password", "")
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("set --s"), ["--secret"])
        self.assertIn("network/ssh_probe.", completer.candidates("set --secret "))
        self.assertEqual(completer.candidates("set --secret network/ssh_probe.pass"), ["network/ssh_probe.password="])
        self.assertNotIn("--secret", completer.candidates("set --secret "))

    def test_secret_input_mode_accepts_plain_modes(self):
        """Protect secret input mode accepts plain modes behavior from regressions."""
        completer = Completer(self.registry)
        self.assertEqual(secret_input_mode(completer), "auto")
        self.registry.varstore.set("secret.input-mode", "plain")
        self.assertEqual(secret_input_mode(completer), "plain")
        self.registry.varstore.set("secret.input-mode", "plaintext")
        self.assertEqual(secret_input_mode(completer), "plaintext")
        self.registry.varstore.set("secret.input-mode", "askpass")
        self.assertEqual(secret_input_mode(completer), "askpass")

    def test_effective_secret_input_auto_uses_desktop_askpass_when_available(self):
        completer = Completer(self.registry)
        with patch("bywaf.secret.input.desktop_askpass_available", return_value=True):
            self.assertEqual(prompt_secret_mode(completer), "askpass")

    def test_effective_secret_input_auto_uses_block_when_desktop_prompt_unavailable(self):
        completer = Completer(self.registry)
        with patch("bywaf.secret.input.desktop_askpass_available", return_value=False):
            self.assertEqual(prompt_secret_mode(completer), "block")

    def test_effective_secret_input_respects_explicit_block_in_desktop(self):
        completer = Completer(self.registry)
        self.registry.varstore.set("secret.input-mode", "block")
        with patch("bywaf.secret.input.desktop_askpass_available", return_value=True):
            self.assertEqual(prompt_secret_mode(completer), "block")

    def test_secret_input_block_opens_only_for_var_secret_assignments(self):
        self.assertEqual(open_secret_assignment_name("set --secret ssh_probe.password="), "ssh_probe.password")
        self.assertEqual(open_secret_assignment_name("set ssh_probe.password= --secret"), "ssh_probe.password")
        self.assertIsNone(open_secret_assignment_name("vars --secret ssh_probe.password="))
        self.assertIsNone(open_secret_assignment_name("set password="))
        self.assertIsNone(open_secret_assignment_name("set ssh_probe.password --secret="))

    def test_secret_input_block_drops_when_assignment_prefix_is_edited(self):
        text = f"set --secret pw={SECRET_BLOCK_VALUE}"
        span_start = text.index(SECRET_BLOCK_VALUE)
        state = PromptSecretInputState()
        state.span = PromptSecretSpan("pw", span_start, span_start + len(SECRET_BLOCK_VALUE), "secret")
        buffer = FakePromptBuffer(text, span_start)

        # Editing the assignment prefix invalidates the protected secret span
        # because the hidden value can no longer be safely associated with it.
        state.delete_before_cursor(buffer)

        self.assertEqual(buffer.text, "set --secret pw")
        self.assertIsNone(state.span)

    def test_secret_input_block_drops_when_assignment_prefix_is_forward_deleted(self):
        text = f"set --secret pw={SECRET_BLOCK_VALUE}"
        span_start = text.index(SECRET_BLOCK_VALUE)
        state = PromptSecretInputState()
        state.span = PromptSecretSpan("pw", span_start, span_start + len(SECRET_BLOCK_VALUE), "secret")
        buffer = FakePromptBuffer(text, span_start - 1)

        state.delete_at_cursor(buffer)

        self.assertEqual(buffer.text, "set --secret pw")
        self.assertIsNone(state.span)

    def test_secret_input_escape_semantics_leave_after_and_preserve_value(self):
        text = f"set --secret pw={SECRET_BLOCK_VALUE}"
        span_start = text.index(SECRET_BLOCK_VALUE)
        state = PromptSecretInputState()
        state.span = PromptSecretSpan("pw", span_start, span_start + len(SECRET_BLOCK_VALUE), "secret")
        buffer = FakePromptBuffer(text, span_start)
        app = FakePromptApp()

        state.leave_after(buffer, app)

        self.assertEqual(buffer.cursor_position, span_start + len(SECRET_BLOCK_VALUE))
        self.assertFalse(state.span.focused)
        self.assertEqual(state.span.value, "secret")
        self.assertTrue(app.output.shown)
        self.assertTrue(app.invalidated)

    def test_secret_input_toolbar_only_shows_while_secret_block_is_focused(self):
        state = PromptSecretInputState()
        self.assertIsNone(secret_input_bottom_toolbar(state))
        state.span = PromptSecretSpan("pw", 16, 16 + len(SECRET_BLOCK_VALUE), "secret")
        self.assertIn("Secret:", str(secret_input_bottom_toolbar(state)))
        state.clear_focus()
        self.assertIsNone(secret_input_bottom_toolbar(state))

    def test_completes_history_time_window_selectors(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("history si"), ["since="])
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
                # Completion preserves the exact @ expansion mode prefix typed
                # by the operator instead of normalizing to plain filenames.
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
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            self.assertEqual(completer.candidates("portscanner --from job="), [f"job={job_id}"])
            self.assertEqual(completer.candidates("portscanner --from step="), ["step=1"])
            self.assertEqual(completer.candidates("portscanner --from pipeline="), ["pipeline=1"])
            self.assertIn("serial=run-1", completer.candidates("event serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("event serial="))
            self.assertIn("topic=host.found", completer.candidates("portscanner --from topic="))

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
            self.assertEqual(completer.candidates("event step="), ["step=1"])
            self.assertEqual(completer.candidates("event pipeline="), ["pipeline=1"])
            self.assertIn("serial=run-1", completer.candidates("event serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("event serial="))
            self.assertEqual(completer.candidates("event job="), [f"job={job_id}"])
            self.assertIn("topic=host.found", completer.candidates("event topic="))

    def test_audit_policy_completes_selector_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "policy.evaluated",
                {
                    "commandlet": "hostscanner",
                    "decision": "warn",
                    "warnings": ["198.51.100.10 is outside allowed network scope"],
                    "before": {"targets": ["192.0.2.10", "198.51.100.10"]},
                    "after": {"targets": ["192.0.2.10"]},
                    "job_id": None,
                    "pipeline_id": "pipeline-1",
                    "command_run_id": "run-1",
                },
                "framework",
                pipeline_id="pipeline-1",
                command_run_id="run-1",
            )
            job_id = db.record_job("hostscanner 198.51.100.10", 123, "done")
            completer = Completer(self.registry, db)

            self.assertEqual(completer.candidates("audit list policy d"), ["decision="])
            self.assertIn("decision=warn", completer.candidates("audit list policy decision="))
            self.assertIn("decision=allow", completer.candidates("audit list policy decision="))
            self.assertEqual(completer.candidates("audit list policy plugin=host"), ["plugin=hostscanner"])
            self.assertEqual(completer.candidates("audit list policy target=198"), ["target=198.51.100.10"])
            self.assertEqual(completer.candidates("audit list policy step="), ["step=1"])
            self.assertEqual(completer.candidates("audit list policy pipeline="), ["pipeline=1"])
            self.assertEqual(completer.candidates("audit list policy job="), [f"job={job_id}"])
            self.assertIn("serial=run-1", completer.candidates("audit list policy serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("audit list policy serial="))

    def test_audit_topic_policy_completes_selector_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "plugin.topic.policy",
                {
                    "commandlet": "webfin",
                    "topic": "web.fingerprint",
                    "reason": "unregistered",
                    "decision": "audit",
                    "message": "webfin published topic without a registered schema: web.fingerprint",
                    "pipeline_id": "pipeline-1",
                    "command_run_id": "run-1",
                },
                "webfin",
                pipeline_id="pipeline-1",
                command_run_id="run-1",
            )
            job_id = db.record_job("webfin", 123, "done")
            completer = Completer(self.registry, db)

            self.assertEqual(completer.candidates("audit list topics r"), ["reason="])
            self.assertIn("decision=audit", completer.candidates("audit list topics decision="))
            self.assertIn("decision=enforce", completer.candidates("audit list topics decision="))
            self.assertIn("reason=unregistered", completer.candidates("audit list topics reason="))
            self.assertEqual(completer.candidates("audit list topics plugin=web"), ["plugin=webfin"])
            self.assertEqual(completer.candidates("audit list topics topic=web"), ["topic=web.fingerprint"])
            self.assertEqual(completer.candidates("audit list topics step="), ["step=1"])
            self.assertEqual(completer.candidates("audit list topics pipeline="), ["pipeline=1"])
            self.assertEqual(completer.candidates("audit list topics job="), [f"job={job_id}"])
            self.assertIn("serial=run-1", completer.candidates("audit list topics serial="))
            self.assertIn("serial=pipeline-1", completer.candidates("audit list topics serial="))

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
            self.assertIn("artifacts=1", completer.completion_meta("step=1", "event step=", "step="))
            self.assertIn("artifacts=1", completer.completion_meta("pipeline=1", "event pipeline=", "pipeline="))
            self.assertIn("artifacts=1", completer.completion_meta(f"job={job_id}", "event job=", "job="))
            self.assertEqual(completer.completion_meta("pipeline=", "report ", ""), "")
            self.assertEqual(completer.completion_meta("pipeline=pr", "report pipeline=pr", "pipeline=pr"), "")

    def test_tokens_after_last_pipe(self):
        self.assertEqual(tokens_after_last_pipe(["hostscanner", "x", "|", "por"]), ["por"])
