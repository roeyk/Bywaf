# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility."""

from tests.registry_completion.support import *  # noqa: F403,F405
class RegistryFilesystemPluginTests(unittest.TestCase):
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
            self.assertEqual(registry.varstore.get("scanners/example.answer"), "42")

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
            self.assertEqual(registry.commandlet_origin("example"), "filesystem")

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
            self.assertEqual(registry.varstore.get("scanners/example.answer"), "42")

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

    def test_filesystem_manifest_rejects_database_actions_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', database_actions=('view',))\n"
                "    def run(self, context, args, input_events):\n"
                "        return ()\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
                "database.actions.view = false\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "database_actions mismatch"):
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

    def test_filesystem_manifest_rejects_provider_variable_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "plugins")
            plugin_dir = root / "scanners" / "example"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', provider_variables=('proxy',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            (plugin_dir / "bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                "capabilities = []\n"
                "provider_variables = []\n"
            )
            config = Path(tmp, "plugins.toml")
            config.write_text('default_plugins = ["scanners/example"]\n')

            with self.assertRaisesRegex(ValueError, "provider_variables mismatch"):
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
