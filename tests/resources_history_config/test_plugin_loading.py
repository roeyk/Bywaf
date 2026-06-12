# ruff: noqa: F403,F405
"""Resources/history/config tests split by responsibility.

Coverage focus: resources history config plugin loading regression behavior.
"""

from tests.resources_history_config.support import *  # noqa: F403,F405
class ResourcesHistoryPluginLoadingTests(unittest.TestCase):
    """Groups regression coverage for resources/history/config tests split by responsibility."""
    def test_load_script_records_auditable_serial(self):
        """Protect load script records auditable serial behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(tmp, "script.bywaf")
            script.write_text("set loaded.value=yes\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"script load file={script}")
            loaded = runner.db.events_for_topic("resource.script.loaded")[0]
            serial = loaded.payload["serial"]
            self.assertTrue(str(serial).startswith("script-"))
            self.assertIn(str(serial), runner.db.serials())
            commands = runner.db.events_for_serial(str(serial))
            self.assertEqual([event.topic for event in commands], ["resource.script.loaded", "resource.script.command"])
            self.assertEqual(commands[1].payload["command"], "set loaded.value=yes")

    def test_load_plugin_records_auditable_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
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
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force")
            self.assertIn("example", runner.registry.names())
            loaded = runner.db.events_for_topic("resource.plugin.loaded")[0]
            serial = loaded.payload["serial"]
            self.assertTrue(str(serial).startswith("plugin-"))
            self.assertEqual(loaded.payload["commandlet"], "example")
            self.assertEqual(runner.db.events_for_serial(str(serial)), [loaded])

    def test_pload_loads_plugin_resource(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pload {plugin_dir} --force")
            self.assertIn("example", runner.registry.names())

    def test_plugin_load_use_selects_single_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use", state)
            self.assertEqual(state.active_context, "example")

    def test_plugin_load_prints_declared_variable_stubs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_external_plugin_with_vars(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/example --force", state)
            text = output.getvalue()
            self.assertIn("plugin variables:", text)
            self.assertIn("first=", text)
            self.assertIn("second=", text)
            self.assertIn("token=", text)
            self.assertIn("lab.proxy=", text)
            self.assertNotIn("hidden=", text)

    def test_plugin_load_use_lists_multiple_commandlets_without_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use", state)
            self.assertIsNone(state.active_context)
            self.assertIn("loaded plugin exposes multiple commandlets", output.getvalue())
            self.assertIn("use first", output.getvalue())
            self.assertIn("use second", output.getvalue())

    def test_plugin_load_use_specific_commandlet_selects_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force use=second", state)
            self.assertEqual(state.active_context, "multi/second")

    def test_plugin_load_rejects_value_carrying_use_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force --use=second", state)
            self.assertIsNone(state.active_context)
            self.assertIn("usage: plugin load=<path>", output.getvalue())

    def test_plugin_load_path_places_provider_in_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/tools --force", state)
                dispatch_repl_line(runner, "use lab/tools/example", state)
            self.assertEqual(state.active_context, "lab/tools/example")
            self.assertTrue(runner.registry.has_commandlet("lab/tools/example"))

    def test_use_provider_selects_manifest_default_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp), default_commandlet="second")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/multi --force", state)
                dispatch_repl_line(runner, "use lab/multi", state)
            self.assertEqual(state.active_context, "lab/multi/second")

    def test_use_provider_without_default_lists_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} path=lab/multi --force", state)
                dispatch_repl_line(runner, "use lab/multi", state)
            self.assertIsNone(state.active_context)
            self.assertIn("lab/multi exposes multiple commandlets", output.getvalue())
            self.assertIn("first", output.getvalue())
            self.assertIn("second", output.getvalue())

    def test_use_accepts_provider_qualified_commandlet_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_multi_external_plugin(Path(tmp))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "use multi/second", state)
            self.assertEqual(state.active_context, "multi/second")

    def test_dispatch_accepts_provider_qualified_commandlet_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "example/example", state)
            events = runner.db.events_for_topic("example.done")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].source, "example")

    def test_external_plugin_enforces_declared_capabilities_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=False)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("capability policy denies undeclared capability", output.getvalue())
            missing = runner.db.events_for_topic("plugin.capability.missing")
            self.assertEqual(missing[0].payload["capability"], "framework.console.output")
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested"), [])

    def test_external_plugin_declared_capability_runs_under_default_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("hello from external", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("plugin.capability.missing"), [])

    def test_operator_can_downgrade_external_plugin_capability_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.capabilities.mode", "audit")
            state = ShellState()
            plugin_dir = write_console_external_plugin(Path(tmp), declare_output=False)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force", state)
                dispatch_repl_line(runner, "external_console", state)

            self.assertIn("hello from external", output.getvalue())
            missing = runner.db.events_for_topic("plugin.capability.missing")
            self.assertEqual(missing[0].payload["capability"], "framework.console.output")

    def test_fully_qualified_commandlet_ignores_active_use_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            alpha = write_simple_external_plugin(Path(tmp), "alpha")
            beta = write_simple_external_plugin(Path(tmp), "beta")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={alpha} --force", state)
                dispatch_repl_line(runner, f"plugin load={beta} --force", state)
                dispatch_repl_line(runner, "use alpha", state)
                dispatch_repl_line(runner, "beta/beta", state)
            self.assertEqual(state.active_context, "alpha")
            self.assertEqual(len(runner.db.events_for_topic("alpha.done")), 0)
            self.assertEqual(len(runner.db.events_for_topic("beta.done")), 1)

    def test_script_fully_qualified_commandlet_ignores_active_use_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            alpha = write_simple_external_plugin(Path(tmp), "alpha")
            beta = write_simple_external_plugin(Path(tmp), "beta")
            script = Path(tmp, "script.bywaf")
            script.write_text("use alpha\nbeta/beta\n")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={alpha} --force", state)
                dispatch_repl_line(runner, f"plugin load={beta} --force", state)
                run_script(runner, script, state)
            self.assertEqual(state.active_context, "alpha")
            self.assertEqual(len(runner.db.events_for_topic("alpha.done")), 0)
            self.assertEqual(len(runner.db.events_for_topic("beta.done")), 1)

    def test_run_executes_active_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            plugin_dir = write_simple_external_plugin(Path(tmp), "example")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pload {plugin_dir} --force --use", state)
                dispatch_repl_line(runner, "run", state)
            events = runner.db.events_for_topic("example.done")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].payload["ok"], True)

    def test_run_requires_active_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "run", ShellState())
            self.assertIn("no active commandlet", output.getvalue())

    def test_load_plugin_refuses_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin')\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"plugin load={plugin_dir}")
            self.assertIn("warning: refusing external plugin", output.getvalue())
            self.assertNotIn("example", runner.registry.names())

    def test_load_plugin_audits_manifest_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            plugin_dir = Path(tmp, "example")
            plugin_dir.mkdir()
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', capabilities=('network.connect',))\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[plugin]\n"
                "library_backed = true\n\n"
                "[[commandlets]]\n"
                'name = "example"\n'
                'capabilities = ["network.connect"]\n'
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"plugin load={plugin_dir} --force")
            loaded = runner.db.events_for_topic("resource.plugin.loaded")[0]
            self.assertEqual(loaded.payload["manifest"], str(plugin_dir / "bywaf.plugin.toml"))
            self.assertEqual(loaded.payload["traits"]["library_backed"], True)
            self.assertEqual(loaded.payload["capabilities"]["example"], ["network.connect"])
            self.assertRegex(str(loaded.payload["manifest_sha256"]), r"^[0-9a-f]{64}$")
