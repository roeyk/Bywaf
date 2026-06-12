"""Plugin checker tests for test diagnostics.

Coverage focus: plugin check diagnostics regression behavior.
"""

from pathlib import Path
import tempfile
import unittest

from scripts.plugin_check import check_plugin, render_llm_feedback, render_text
from tests.plugin_check_fixtures import (
    write_decorated_factory_fixture,
    write_parser_mismatch_fixture,
    write_plugin_fixture,
)


class TestDiagnosticsTests(unittest.TestCase):
    """Groups regression coverage for plugin checker tests for test diagnostics."""
    def test_check_plugin_reports_invalid_argument_decorator_keyword(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                decorators='@argument("url", "target URL", required=True, nargs="+")\n',
                imports="from bywaf.plugin import argument\n",
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-argument-decorator-keyword")
            feedback = render_llm_feedback(report)
            self.assertIn("Put argparse behavior such as nargs", feedback)

    def test_check_plugin_reports_decorator_on_plugin_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_decorated_factory_fixture(Path(tmp))

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "decorator-on-plugin-factory")

    def test_check_plugin_reports_missing_factory_for_decorated_commandlet(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp) / "example"
            plugin_dir.mkdir()
            plugin_dir.joinpath("plugin.py").write_text(
                "from bywaf.plugin import commandlet\n"
                "\n"
                "@commandlet\n"
                "def example(context, cfg, input_events):\n"
                "    del context\n"
                "    del input_events\n"
                "    yield {'ok': cfg.target}\n",
                encoding="utf-8",
            )
            plugin_dir.joinpath("bywaf.plugin.toml").write_text(
                "[plugin]\n"
                'version = "0.1.0"\n\n'
                "[[commandlets]]\n"
                'name = "example"\n'
                'emits = ["example.observed"]\n'
                "capabilities = []\n"
                "database.actions.write = true\n"
                "\n"
                "[[commandlets.arguments]]\n"
                'name = "target"\n'
                'description = "Target value"\n'
                "\n"
                "[[event_schemas]]\n"
                'topic = "example.observed"\n'
                'version = "1"\n'
                'summary = "Example observation."\n'
                "\n"
                "[[event_schemas.fields]]\n"
                'name = "ok"\n'
                'type = "str"\n'
                'description = "Observed value."\n',
                encoding="utf-8",
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            diagnostics = [item["code"] for item in report["diagnostics"]]
            self.assertIn("missing-plugin-factory", diagnostics)
            feedback = render_llm_feedback(report)
            self.assertIn("def plugin() -> Commandlet", feedback)
            self.assertIn("plugin().run(...)", feedback)

    def test_check_plugin_reports_invalid_candidate_payload_keyword(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                imports="from bywaf.finding import candidate_payload\n",
                run_body="        yield candidate_payload(title='t', classification='wrong', target={})\n",
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-candidate-payload-keyword")

    def test_check_plugin_accepts_candidate_payload_subjects_keyword(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                imports="from bywaf.finding import candidate_payload\n",
                run_body=(
                    "        yield candidate_payload("
                    "title='t', finding_class='web.header.missing_hsts', "
                    "target={'host': 'example.test'}, subjects={'target.host': 'host'})\n"
                ),
            )

            report = check_plugin(plugin_dir)

            diagnostics = [item["code"] for item in report["diagnostics"]]
            self.assertNotIn("invalid-candidate-payload-keyword", diagnostics)

    def test_check_plugin_requires_manifest_emits_for_shared_published_topic(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=("db.write:host.found",),
                emits=("host.found",),
                manifest_emits=(),
                run_body='        context.events.publish("host.found", {"host": "127.0.0.1"})\n',
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["missing_shared_emits"], ["host.found"])
            feedback = render_llm_feedback(report)
            self.assertIn("Missing shared event declaration: host.found", feedback)

    def test_check_plugin_warns_about_declared_emit_without_registered_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=("db.write:example.unregistered",),
                emits=("example.unregistered",),
                manifest_emits=("example.unregistered",),
                run_body='        context.events.publish("example.unregistered", {"ok": True})\n',
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["unregistered_declared_emits"], ["example.unregistered"])
            self.assertIn("unregistered declared emits: example.unregistered", render_text(report))
            feedback = render_llm_feedback(report)
            self.assertIn("Unregistered declared event topic: example.unregistered", feedback)
            self.assertIn("global.topic.unregistered.mode", feedback)

    def test_check_plugin_validates_literal_shared_event_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=("db.write:port.open",),
                emits=("port.open",),
                manifest_emits=("port.open",),
                run_body='        context.events.publish("port.open", {"host": "127.0.0.1", "port": 80})\n',
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-shared-event-payload")
            self.assertIn("port.open.protocol is required", report["diagnostics"][0]["message"])

    def test_check_plugin_validates_assigned_literal_shared_event_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=("db.write:port.open",),
                emits=("port.open",),
                manifest_emits=("port.open",),
                run_body=(
                    '        payload = {"host": "127.0.0.1", "port": 80}\n'
                    '        context.events.publish("port.open", payload)\n'
                ),
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-shared-event-payload")
            self.assertIn("port.open.protocol is required", report["diagnostics"][0]["message"])

    def test_check_plugin_validates_literal_plugin_owned_event_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=("db.write:example.session.observed",),
                emits=("example.session.observed",),
                manifest_emits=("example.session.observed",),
                manifest_extra=(
                    "\n[[event_schemas]]\n"
                    'topic = "example.session.observed"\n'
                    'summary = "Example session fact."\n'
                    "\n[[event_schemas.fields]]\n"
                    'name = "host"\n'
                    'type = "str"\n'
                    "required = true\n"
                    "\n[[event_schemas.fields]]\n"
                    'name = "username"\n'
                    'type = "str"\n'
                    "required = true\n"
                ),
                run_body='        context.events.publish("example.session.observed", {"host": "dc01"})\n',
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-shared-event-payload")
            self.assertIn("example.session.observed.username is required", report["diagnostics"][0]["message"])

    def test_check_plugin_reports_boolean_option_without_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                decorators='@option("confirm", "perform confirmation")\n',
                imports="from bywaf.plugin import option\n",
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "boolean-option-missing-default")
            feedback = render_llm_feedback(report)
            self.assertIn("explicit string default and choices", feedback)

    def test_check_plugin_reports_declared_option_missing_from_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_parser_mismatch_fixture(Path(tmp))

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            codes = [item["code"] for item in report["diagnostics"]]
            self.assertIn("commandlet-option-parser-mismatch", codes)
            self.assertIn("target", "\n".join(report["errors"]))


if __name__ == "__main__":
    unittest.main()
