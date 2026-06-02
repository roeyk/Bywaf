"""Plugin checker tests for test manifest basics."""

from pathlib import Path
import tempfile
import unittest

from bywaf.tools.plugin_check import analyze_plugin_source
from scripts.plugin_check import check_plugin, render_llm_feedback
from tests.plugin_check_fixtures import write_multifile_plugin_fixture, write_plugin_fixture


class TestManifestBasicsTests(unittest.TestCase):
    def test_check_plugin_accepts_valid_package(self):
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
