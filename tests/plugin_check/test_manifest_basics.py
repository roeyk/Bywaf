"""Plugin checker tests for test manifest basics.

Coverage focus: plugin check manifest basics regression behavior.
"""

from pathlib import Path
import tempfile
import unittest

from bywaf.tools.plugin_check import analyze_plugin_source
from scripts.plugin_check import check_plugin, render_llm_feedback
from tests.plugin_check_fixtures import write_multifile_plugin_fixture, write_plugin_fixture


class TestManifestBasicsTests(unittest.TestCase):
    """Groups regression coverage for plugin checker tests for test manifest basics."""
    def test_check_plugin_accepts_valid_package(self):
        """Protect check plugin accepts valid package behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["plugin_version"], "0.1.0")
            self.assertEqual(report["commandlets"], ["example"])
            self.assertEqual(report["triggers"], [])
            self.assertEqual(report["errors"], [])

    def test_check_plugin_requires_plugin_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(manifest.read_text().replace('version = "0.1.0"\n\n', ""))

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("manifest [plugin].version is required", report["errors"])

    def test_check_plugin_rejects_unknown_top_level_manifest_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(manifest.read_text() + "\n[capabilities]\nnetwork = { connect = true }\n")

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("manifest has unknown key(s): capabilities", report["errors"][0])

    def test_check_plugin_rejects_unknown_plugin_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(manifest.read_text().replace("[plugin]\n", '[plugin]\nname = "example"\nauthor = "alice"\n'))

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("plugin has unknown key(s): author, name", report["errors"][0])

    def test_check_plugin_rejects_unknown_argument_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                manifest_extra=(
                    "\n[[commandlets.arguments]]\n"
                    'name = "url"\n'
                    'description = "target URL"\n'
                    "required = true\n"
                    "positional = true\n"
                ),
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("arguments entry 1 has unknown key(s): positional, required", report["errors"][0])

    def test_check_plugin_rejects_unknown_option_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                manifest_extra=(
                    "\n[[commandlets.options]]\n"
                    'name = "timeout"\n'
                    'description = "timeout seconds"\n'
                    'type = "float"\n'
                    "required = true\n"
                ),
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("options entry 1 has unknown key(s): required", report["errors"][0])

    def test_check_plugin_rejects_unknown_event_schema_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                manifest_extra=(
                    "\n[[event_schemas]]\n"
                    'topic = "example.event"\n'
                    'description = "not a supported key"\n'
                    "\n[[event_schemas.fields]]\n"
                    'name = "url"\n'
                ),
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("event_schemas entry 1 has unknown key(s): description", report["errors"][0])

    def test_check_plugin_rejects_invalid_event_schema_type_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                manifest_extra=(
                    "\n[[event_schemas]]\n"
                    'topic = "example.event"\n'
                    'summary = "example event"\n'
                    "\n[[event_schemas.fields]]\n"
                    'name = "url"\n'
                    'type = "string"\n'
                ),
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("type must be one of: any, bool, dict, int, list, number, str", report["errors"][0])

    def test_llm_feedback_gives_manifest_version_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(manifest.read_text().replace('version = "0.1.0"\n\n', ""))

            feedback = render_llm_feedback(check_plugin(plugin_dir))

            self.assertIn("Missing required manifest field: [plugin].version", feedback)
            self.assertIn('version = "0.1.0"', feedback)
            self.assertNotIn("correct the plugin so scripts/plugin_check.py can import", feedback)

    def test_check_plugin_rejects_incompatible_bywaf_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(
                manifest.read_text().replace('version = "0.1.0"\n\n', 'version = "0.1.0"\nrequires_bywaf = ">99.0.0"\n\n')
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("requires Bywaf >99.0.0", report["errors"][0])

    def test_check_plugin_accepts_explicit_schema_and_plugin_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                manifest_extra=(
                    "\n[[event_schemas]]\n"
                    'topic = "example.event"\n'
                    'summary = "example event"\n'
                    "\n[[event_schemas.fields]]\n"
                    'name = "url"\n'
                    'type = "str"\n'
                ),
            )
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(
                manifest.read_text().replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_schemas = ["example.event"]\nrequires_plugins = ["http.probe"]\n',
                )
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"], report["errors"])

    def test_check_plugin_rejects_missing_required_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(
                manifest.read_text().replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_plugins = ["missing.provider"]\n',
                )
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("missing required plugin: missing.provider", report["errors"])

    def test_check_plugin_rejects_missing_required_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())
            manifest = plugin_dir.joinpath("bywaf.plugin.toml")
            manifest.write_text(
                manifest.read_text().replace(
                    'version = "0.1.0"\n',
                    'version = "0.1.0"\nrequires_schemas = ["missing.schema"]\n',
                )
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("missing required schema: missing.schema", report["errors"])

    def test_check_plugin_accepts_multifile_relative_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_multifile_plugin_fixture(Path(tmp))

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["commandlets"], ["example"])
            self.assertEqual(report["errors"], [])

    def test_source_analysis_accepts_single_file_plugin_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "single.py"
            path.write_text('def run(context):\n    context.output("ok")\n')

            analysis = analyze_plugin_source(path)

            self.assertEqual(analysis.inferred_capabilities, ("framework.console.output",))


if __name__ == "__main__":
    unittest.main()
