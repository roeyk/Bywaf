# ruff: noqa: F403,F405
"""Config/plugin tests split by responsibility.

Coverage focus: config plugin specs regression behavior.
"""

from tests.config_plugin.support import *  # noqa: F403,F405
class ConfigPluginSpecTests(unittest.TestCase):
    """Groups regression coverage for config/plugin tests split by responsibility."""
    def test_default_settings(self):
        """Protect default settings behavior from regressions."""
        settings = default_settings()
        self.assertIsInstance(settings, Settings)
        self.assertEqual(settings.database.as_posix(), ".bywaf/bywaf.sqlite3")
        self.assertEqual(settings.config.as_posix(), ".bywaf/config.toml")
        self.assertEqual(settings.history.as_posix(), ".bywaf/history.bywaf")
        self.assertEqual(settings.plugin_dir.as_posix(), ".bywaf/plugins")
        self.assertEqual(settings.script_dir.as_posix(), ".bywaf/scripts")
        self.assertEqual(settings.database_dir.as_posix(), ".bywaf/db")
        self.assertEqual(settings.config_dir.as_posix(), ".bywaf/config")

    def test_option_spec_defaults(self):
        """Protect option spec defaults behavior from regressions."""
        option = OptionSpec("ports", "ports to scan")
        self.assertEqual(option.choices, ())
        self.assertFalse(option.secret)

    def test_command_spec_defaults(self):
        """Protect command spec defaults behavior from regressions."""
        spec = CommandSpec("name", "description")
        self.assertEqual(spec.options, ())
        self.assertEqual(spec.arguments, ())
        self.assertEqual(spec.emits, ())

    def test_argument_spec_defaults(self):
        argument = ArgumentSpec("path")
        self.assertTrue(argument.required)
        self.assertEqual(argument.completion, CompletionSpec())

    def test_commandlet_decorators_build_spec(self):
        @commandlet(
            name="hello",
            description="say hello",
            usage="hello [name]",
            examples=("hello world",),
            emits=("hello.greeting",),
            capabilities=("framework.console.output",),
        )
        @option("timeout", "timeout seconds", default="5")
        @option("password", "password", secret=True)
        @option("uppercase", "uppercase output", default="false", choices=("true", "false"))
        @argument("suffix", "suffix", required=False)
        @argument("name", "name to greet", required=False, completion="plugin")
        class Hello:
            pass

        spec = getattr(Hello, "spec")
        self.assertEqual(spec.name, "hello")
        self.assertEqual(spec.arguments[0].name, "suffix")
        self.assertEqual(spec.arguments[1].name, "name")
        self.assertFalse(spec.arguments[1].required)
        self.assertEqual(spec.arguments[1].completion, CompletionSpec("plugin"))
        self.assertEqual(spec.options[0].name, "timeout")
        self.assertEqual(spec.options[1].name, "password")
        self.assertTrue(spec.options[1].secret)
        self.assertEqual(spec.options[2].name, "uppercase")
        self.assertEqual(spec.options[2].choices, ("true", "false"))
        self.assertEqual(spec.emits, ("hello.greeting",))
        self.assertEqual(spec.capabilities, ("framework.console.output",))

    def test_normalize_argv_rejects_shell_string(self):
        with self.assertRaisesRegex(TypeError, "sequence of strings"):
            normalize_argv("echo hello")

    def test_normalize_argv_rejects_empty_argv(self):
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            normalize_argv([])

    def test_format_table_aligns_mapping_rows(self):
        lines = format_table([{"name": "one", "value": 1}], ("name", "value"))
        self.assertEqual(lines, ["name  value", "----  -----", "one   1    "])
