"""Plugin checker tests for test capability inference.

Coverage focus: plugin check capability inference regression behavior.
"""

from pathlib import Path
import tempfile
import unittest

from scripts.plugin_check import check_plugin, render_llm_feedback, render_text
from tests.plugin_check_fixtures import write_plugin_fixture


class TestCapabilityInferenceTests(unittest.TestCase):
    """Groups regression coverage for plugin checker tests for test capability inference."""
    def test_check_plugin_reports_manifest_drift(self):
        """Protect check plugin reports manifest drift behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",), manifest_capabilities=())

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("capabilities mismatch", report["errors"][0])

    def test_check_plugin_reports_ast_inferred_missing_capabilities(self):
        """Protect check plugin reports ast inferred missing capabilities behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body='        context.process.run(["echo", "ok"])\n',
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertIn("artifact.write", report["inferred_capabilities"])
            self.assertIn("framework.process.run", report["inferred_capabilities"])
            self.assertIn("artifact.write", report["missing_capabilities"])
            self.assertIn("framework.process.run", report["missing_capabilities"])
            self.assertEqual(report["errors"], [])
            self.assertEqual(report["evidence"][0]["kind"], "framework_call")

    def test_check_plugin_infers_artifact_store_access_capabilities(self):
        """Protect check plugin infers artifact store access capabilities behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body='        context.artifact_store("example", read_access=True, write_access=True)\n',
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertIn("artifact.read", report["inferred_capabilities"])
            self.assertIn("artifact.write", report["inferred_capabilities"])
            self.assertIn("artifact.read", report["missing_capabilities"])
            self.assertIn("artifact.write", report["missing_capabilities"])

    def test_check_plugin_warns_on_unspecified_artifact_store_access(self):
        """Protect check plugin warns on unspecified artifact store access behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body='        context.artifact_store("example")\n',
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["warnings"][0]["kind"], "artifact_store_access_unspecified")
            self.assertEqual(report["warnings"][0]["confidence"], "high")

    def test_check_plugin_strict_inference_fails_on_missing_capabilities(self):
        """Protect check plugin strict inference fails on missing capabilities behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body='        context.events.publish("example.event", {})\n',
            )

            report = check_plugin(plugin_dir, strict_inference=True)

            self.assertFalse(report["ok"])
            self.assertIn("db.write:example.event", report["missing_capabilities"])
            self.assertEqual(report["capability_codes"]["db.write:example.event"], "C102.617506")
            self.assertIn("missing inferred capabilities", report["errors"][0])
            self.assertIn("db.write:example.event=C102.617506", render_text(report))
            feedback = render_llm_feedback(report)
            self.assertIn("Missing capability declaration: db.write:example.event (C102.617506)", feedback)
            self.assertIn("bywaf.plugin.toml [[commandlets]] capabilities list", feedback)
            self.assertIn("legacy code-only plugins", feedback)

    def test_check_plugin_infers_context_alias_parameter_calls(self):
        """Protect check plugin infers context alias parameter calls behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body=(
                    "        def emit(ctx):\n"
                    '            ctx.events.publish("example.event", {})\n'
                    "        emit(context)\n"
                ),
            )

            report = check_plugin(plugin_dir, strict_inference=True)

            self.assertFalse(report["ok"])
            self.assertIn("db.write:example.event", report["missing_capabilities"])
            self.assertIn("example.event", report["inferred_emits"])

    def test_check_plugin_warns_on_direct_network_import(self):
        """Protect check plugin warns on direct network import behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                imports="import socket\n",
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["warnings"][0]["capability"], "network.connect")
            self.assertEqual(report["capability_codes"]["network.connect"], "C401")
            self.assertEqual(report["warnings"][0]["kind"], "direct_network_import")
            self.assertIn("direct network.connect (C401) use detected", render_llm_feedback(report))

    def test_check_plugin_does_not_warn_on_urllib_parse_after_urllib_request_import(self):
        """Protect check plugin does not warn on urllib parse after urllib request import behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                imports="import urllib.request\nimport urllib.parse\n",
                run_body='        urllib.parse.urlparse("https://example.test/")\n        yield {"ok": True}\n',
            )

            report = check_plugin(plugin_dir)

            warning_details = [warning["detail"] for warning in report["warnings"]]
            self.assertTrue(any("import urllib.request" in detail for detail in warning_details))
            self.assertFalse(any("urlparse" in detail for detail in warning_details))


if __name__ == "__main__":
    unittest.main()
