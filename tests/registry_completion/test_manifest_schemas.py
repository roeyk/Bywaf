# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility.

Coverage focus: registry completion manifest schemas regression behavior.
"""

from tests.registry_completion.support import *  # noqa: F403,F405
class RegistryManifestSchemaTests(unittest.TestCase):
    """Groups regression coverage for registry and completion tests split by responsibility."""
    def test_plugin_manifest_tool_infers_secret_options(self):
        """Protect plugin manifest tool infers secret options behavior from regressions."""
        class Example:
            spec = CommandSpec(
                "example",
                "example plugin",
                options=(OptionSpec("password", "password", secret=True),),
                consumes=("host.found",),
                emits=("port.open",),
                capabilities=("framework.secret.resolve",),
            )

            def run(self, context, args, input_events):
                yield {"ok": True}

        text = manifest_from_plugins((Example(),))
        self.assertIn('name = "example"', text)
        self.assertIn('  "framework.secret.resolve",', text)
        self.assertIn('secret_options = ["password"]', text)
        self.assertIn('consumes = ["host.found"]', text)
        self.assertIn('emits = ["port.open"]', text)

    def test_filesystem_manifest_rejects_emits_mismatch_when_declared(self):
        """Protect filesystem manifest rejects emits mismatch when declared behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp)
            plugin_dir.joinpath("plugin.py").write_text(
                "from bywaf.plugin import CommandSpec\n"
                "class Example:\n"
                "    spec = CommandSpec('example', 'example plugin', emits=('host.found',))\n"
                "    def run(self, context, args, input_events):\n"
                "        yield {'ok': True}\n"
                "def plugin():\n"
                "    return Example()\n"
            )
            plugin_dir.joinpath("bywaf.plugin.toml").write_text(
                "[[commandlets]]\n"
                'name = "example"\n'
                'emits = ["port.open"]\n'
            )

            with self.assertRaisesRegex(ValueError, "emits mismatch"):
                load_filesystem_plugin_package(plugin_dir, manifest_trust=PluginManifestTrust(catalog_verified=True))

    def test_plugin_manifest_tool_generates_trigger_specs(self):
        """Protect plugin manifest tool generates trigger specs behavior from regressions."""
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

    def test_plugin_manifest_tool_can_render_event_schemas(self):
        """Protect plugin manifest tool can render event schemas behavior from regressions."""
        class Example:
            spec = CommandSpec("example", "example plugin")

            def run(self, context, args, input_events):
                yield {"ok": True}

        text = manifest_from_plugins(
            (Example(),),
            event_schemas=(
                EventSchema(
                    "example.session.observed",
                    "Example session fact.",
                    (
                        FieldSchema("host", "str", True, "Session host."),
                        FieldSchema("access", "str", False, allowed=("read", "write")),
                    ),
                    version="2",
                ),
            ),
        )

        self.assertIn("[[event_schemas]]", text)
        self.assertIn('topic = "example.session.observed"', text)
        self.assertIn('version = "2"', text)
        self.assertIn("[[event_schemas.fields]]", text)
        self.assertIn('allowed = ["read", "write"]', text)

    def test_plugin_manifest_parses_plugin_owned_event_schemas(self):
        """Protect plugin manifest parses plugin owned event schemas behavior from regressions."""
        manifest = parse_plugin_manifest_data(
            {
                "commandlets": [{"name": "example"}],
                "event_schemas": [
                    {
                        "topic": "example.session.observed",
                        "version": "2",
                        "summary": "Example session fact.",
                        "fields": [
                            {"name": "host", "type": "str", "required": True},
                            {"name": "access", "type": "str", "allowed": ["read", "write"]},
                        ],
                    }
                ],
            },
            "test.toml",
        )

        self.assertEqual(manifest.event_schemas[0].topic, "example.session.observed")
        self.assertEqual(manifest.event_schemas[0].version, "2")
        self.assertEqual(manifest.event_schemas[0].required_fields, ("host",))

    def test_plugin_manifest_rejects_framework_owned_event_schema(self):
        """Protect plugin manifest rejects framework owned event schema behavior from regressions."""
        with self.assertRaisesRegex(ValueError, "framework-owned"):
            parse_plugin_manifest_data(
                {
                    "commandlets": [{"name": "example"}],
                    "event_schemas": [
                        {
                            "topic": "host.found",
                            "fields": [{"name": "host", "type": "str", "required": True}],
                        }
                    ],
                },
                "test.toml",
            )

    def test_plugin_manifest_rejects_invalid_event_schema_field_type(self):
        with self.assertRaisesRegex(ValueError, "type must be one of"):
            parse_plugin_manifest_data(
                {
                    "commandlets": [{"name": "example"}],
                    "event_schemas": [
                        {
                            "topic": "example.session.observed",
                            "fields": [{"name": "host", "type": "cidr"}],
                        }
                    ],
                },
                "test.toml",
            )
