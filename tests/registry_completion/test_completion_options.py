# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility.

Coverage focus: registry completion completion options regression behavior.
"""

from tests.registry_completion.support import *  # noqa: F403,F405


class RegistryCompletionOptionTests(unittest.TestCase):
    """Option, selector, resource, and prompt-toolkit completion tests.

    The suite verifies the completion layer from the user's partial command
    text rather than by calling lower-level parser helpers directly.
    """

    def setUp(self):
        """Create a fresh registry so option completion sees bundled metadata."""
        self.registry = PluginRegistry.discover()

    def test_completes_plugin_options(self):
        """Protect completes plugin options behavior from regressions."""
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("hostscanner h"), ["host="])
        self.assertIn("port=", completer.candidates("portscanner por"))
        self.assertIn("step=", completer.candidates("portscanner --from "))
        http_options = completer.candidates("http_headers --")
        self.assertNotIn("--help", http_options)
        self.assertIn("port=", completer.candidates("http_headers po"))
        self.assertIn("ssl=", completer.candidates("http_headers ss"))
        self.assertIn("timeout=", completer.candidates("http_headers ti"))
        probe_options = completer.candidates("http_probe --")
        self.assertIn("--silent", probe_options)
        self.assertIn("cookie-file=", completer.candidates("http_probe coo"))
        self.assertIn("firefox-profile=", completer.candidates("http_probe fir"))
        self.assertIn("method=", completer.candidates("http_probe me"))

    def test_inventory_and_report_completion_exposes_last_new_selectors(self):
        """Protect inventory and report completion exposes last new selectors behavior from regressions."""
        completer = Completer(self.registry)
        # All inventory/report views should expose the same runtime scope
        # selectors, while each view can still contribute its own sort keys.
        for command in ("hosts", "services", "web", "wafs", "shares", "routes", "certs", "banners", "paths", "screenshots", "ports"):
            with self.subTest(command=command):
                candidates = completer.candidates(f"{command} --")
                self.assertIn("--last", candidates)
                self.assertIn("--new", candidates)
                self.assertIn("--page", candidates)
                self.assertIn("job=", completer.candidates(f"{command} j"))
                self.assertIn("pipeline=", completer.candidates(f"{command} p"))
                self.assertIn("step=", completer.candidates(f"{command} s"))
                if command == "ports":
                    self.assertIn("sort=", completer.candidates(f"{command} so"))
                else:
                    self.assertTrue(any(item.startswith("sort=") for item in completer.candidates(f"{command} so")))
        report_candidates = completer.candidates("report --")
        self.assertIn("--last", report_candidates)
        self.assertIn("--new", report_candidates)
        self.assertIn("sort=host", completer.candidates("report sort=h"))

    def test_commandlet_topics_complete_only_in_from_selector_context(self):
        """Protect commandlet topics complete only in from selector context behavior from regressions."""
        completer = Completer(self.registry)
        self.assertNotIn("host.found", completer.candidates("hostscanner h"))
        self.assertIn("topic=host.found", completer.candidates("portscanner --from topic=h"))

    def test_artifact_completion_prefers_actions_first(self):
        """Protect artifact completion prefers actions first behavior from regressions."""
        completer = Completer(self.registry)
        # Artifact has an action-first grammar. Completion should suggest
        # subcommands before selector keys, then switch to action-specific args.
        self.assertEqual(
            completer.candidates("artifact "),
            ["attach", "cat", "export", "import", "list", "remove", "replace", "search", "show", "verify"],
        )
        self.assertEqual(completer.candidates("artifact a"), ["attach"])
        self.assertIn("file=", completer.candidates("artifact attach "))
        self.assertIn("limit=", completer.candidates("artifact cat "))
        self.assertIn("file=", completer.candidates("artifact import "))
        self.assertIn("file=", completer.candidates("artifact replace "))
        self.assertIn("dir=", completer.candidates("artifact export "))
        self.assertIn("topic=", completer.candidates("artifact list "))
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
        self.assertFalse(wasd_selection_enabled(completer))
        self.registry.varstore.set(COMPLETION_WASD_SELECTION_VAR, "true")
        self.assertTrue(wasd_selection_enabled(completer))

    def test_control_completion_includes_run_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", command_run_id="run-1")
            completer = Completer(self.registry, db)
            self.assertIn("step=", completer.candidates("pause "))
            self.assertEqual(completer.candidates("pause step="), ["step=run-1"])
            self.assertIn("step=", completer.candidates("signal "))
            self.assertEqual(completer.candidates("signal step="), ["step=run-1"])
            self.assertIn("prune", completer.candidates("signal step=run-1 "))
            self.assertIn("targets=", completer.candidates("signal step=run-1 prune "))

    def test_pipeline_attach_completion_prefers_action_then_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            # Seed one pipeline/step so completion can offer both a local
            # pipeline selector and step-scoped attach options.
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
            self.assertIn("step=1", completer.candidates("pipeline attach pipe-1 portscanner step="))
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

    def test_plugin_without_space_completes_command_name(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("plu"), ["plugin", "plugins"])
        self.assertEqual(completer.candidates("plugin"), ["plugins"])

    def test_load_plugin_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".bywaf", "plugins", "plugin_dir").mkdir(parents=True)
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("plugin load=plug"), ["load=plugin_dir/"])
            finally:
                os.chdir(cwd)

    def test_load_plugin_explicit_path_completes_local_filesystem(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "local_plugin").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("plugin load=./loc"), ["load=./local_plugin/"])
            finally:
                os.chdir(cwd)

    def test_load_plugin_equals_completes_local_plugin_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_plugin = Path(tmp, "local_plugin")
            local_plugin.mkdir()
            (local_plugin / "plugin.py").write_text("def plugin():\n    pass\n")
            Path(tmp, "ordinary_dir").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                candidates = completer.candidates("plugin load=")
                # Only directories that look like plugin roots should be
                # offered for plugin load completion.
                self.assertIn("load=./local_plugin/", candidates)
                self.assertNotIn("load=./ordinary_dir/", candidates)
            finally:
                os.chdir(cwd)

    def test_load_plugin_equals_offers_plugin_root_shortcuts(self):
        completer = Completer(self.registry)
        candidates = completer.candidates("plugin load=")
        self.assertIn("load=./", candidates)
        self.assertIn("load=./.bywaf/plugins/", candidates)
        self.assertIn("load=~/.bywaf/plugins/", candidates)
        self.assertIn("load=/usr/local/share/bywaf/plugins/", candidates)
        self.assertIn("load=/usr/share/bywaf/plugins/", candidates)

    def test_load_plugin_equals_filters_plugin_root_shortcuts(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("plugin load=/usr/"), ["load=/usr/local/share/bywaf/plugins/", "load=/usr/share/bywaf/plugins/"])

    def test_pload_completes_plugin_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".bywaf", "plugins", "plugin_dir").mkdir(parents=True)
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("pload plug"), ["plugin_dir/"])
                self.assertIn("./.bywaf/plugins/", completer.candidates("pload "))
                self.assertEqual(completer.candidates("pload --f"), ["--force"])
            finally:
                os.chdir(cwd)

    def test_load_resource_keywords_complete_from_prefix(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("plugin lo"), ["load="])
        self.assertEqual(completer.candidates("plugin load --f"), ["--force"])
        self.assertIn("path=", completer.candidates("plugin load "))

    def test_set_completion_reads_unloaded_catalog_manifest_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp, ".bywaf", "plugins", "cloud", "aws", "s3", "public_bucket")
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "check"\n'
                "capabilities = []\n"
                'secret_options = ["token"]\n'
                'provider_variables = ["proxy"]\n'
            )
            (plugin_dir / "defaults.toml").write_text("[defaults]\ntimeout = \"5\"\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                candidates = completer.candidates("set cloud/aws/s3/public_bucket/check.")
                provider_candidates = completer.candidates("set cloud/aws/s3/public_bucket.")
            finally:
                os.chdir(cwd)
            self.assertIn("cloud/aws/s3/public_bucket/check.timeout=", candidates)
            self.assertIn("cloud/aws/s3/public_bucket/check.token=", candidates)
            self.assertIn("cloud/aws/s3/public_bucket.proxy=", provider_candidates)

    def test_domain_resource_keywords_complete_from_prefix(self):
        completer = Completer(self.registry)
        self.assertIn("save", completer.candidates("config sa"))
        self.assertIn("load", completer.candidates("history lo"))
        self.assertIn("file=", completer.candidates("script save "))

    def test_load_script_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "script.bywaf").write_text("ls\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("script load file=scr"), ["file=script.bywaf"])
            finally:
                os.chdir(cwd)

    def test_load_history_equals_completes_filesystem_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "history.bywaf").write_text("ls\n")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertEqual(completer.candidates("history load file=his"), ["file=history.bywaf"])
            finally:
                os.chdir(cwd)

    def test_multiple_file_matches_complete_common_base_first(self):
        candidates = ["bywaf.sqlite3", "bywaf/"]
        self.assertEqual(common_completion_prefix("load byw", candidates), "bywaf")
        self.assertEqual(completion_results("load byw", candidates)[0], "bywaf")

    def test_key_value_file_matches_complete_common_base_first(self):
        candidates = ["load=bywaf.sqlite3", "load=bywaf/"]
        self.assertEqual(common_completion_prefix("plugin load=byw", candidates), "load=bywaf")
        self.assertEqual(completion_results("plugin load=byw", candidates)[0], "load=bywaf")

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
                with patch("bywaf.completion.readline.get_line_buffer", return_value="plugin load=by"):
                    self.assertEqual(completer.complete("", 0), "load=bywaf")
            finally:
                os.chdir(cwd)

    def test_key_value_completion_display_strips_key_prefix(self):
        self.assertEqual(display_label("script=README.md"), "README.md")
        self.assertEqual(display_label("plugin=bywaf/"), "bywaf/")

    def test_key_value_completion_uses_custom_menu(self):
        self.assertTrue(
            should_print_completion_menu(
                "script load file=",
                ["file=README.md", "file=tests/"],
            )
        )
        self.assertFalse(should_print_completion_menu("por", ["portscanner"]))
