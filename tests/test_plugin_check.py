"""Tests for plugin check behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

# pyright: reportMissingImports=false

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.plugin_check import check_bundled_plugins, check_plugin, main, render_llm_feedback, render_text
from scripts.plugin_manifest_sign import main as sign_manifest_main
from bywaf.tools.plugin_check import analyze_plugin_source
from tests.plugin_check_fixtures import (
    capture_stdout,
    write_decorated_factory_fixture,
    write_manifest_signing_key,
    write_multifile_plugin_fixture,
    write_parser_mismatch_fixture,
    write_plugin_fixture,
)


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class PluginCheckTests(unittest.TestCase):
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

    def test_check_all_bundled_plugins_json_output(self):
        output = capture_stdout(lambda: main(["--all", "--json"]))

        data = json.loads(output)
        self.assertTrue(data["ok"])
        self.assertGreater(data["checked"], 10)
        self.assertTrue(any(item["entry"] == "http.webfin" for item in data["plugins"]))

    def test_check_bundled_plugins_report_shape(self):
        report = check_bundled_plugins()

        self.assertTrue(report["ok"])
        self.assertEqual(report["plugin"], "bywaf.plugins")
        self.assertEqual(report["errors"], [])

    def test_check_plugin_reports_manifest_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",), manifest_capabilities=())

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("capabilities mismatch", report["errors"][0])

    def test_check_plugin_reports_ast_inferred_missing_capabilities(self):
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
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                run_body='        context.events.publish("example.event", {})\n',
            )

            report = check_plugin(plugin_dir, strict_inference=True)

            self.assertFalse(report["ok"])
            self.assertIn("db.write:example.event", report["missing_capabilities"])
            self.assertIn("missing inferred capabilities", report["errors"][0])

    def test_check_plugin_warns_on_direct_network_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(
                Path(tmp),
                capabilities=(),
                imports="import socket\n",
            )

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["warnings"][0]["capability"], "network.connect")
            self.assertEqual(report["warnings"][0]["kind"], "direct_network_import")

    def test_check_plugin_does_not_warn_on_urllib_parse_after_urllib_request_import(self):
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

    def test_check_plugin_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            output = capture_stdout(lambda: main([str(plugin_dir), "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertEqual(data["commandlets"], ["example"])

    def test_check_plugin_accepts_zip_submission(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            archive = tmp_path / "example.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for path in plugin_dir.rglob("*"):
                    if path.is_file():
                        zipped.write(path, path.relative_to(tmp_path))

            report = check_plugin(archive)

            self.assertTrue(report["ok"])
            self.assertEqual(report["plugin"], str(archive))
            self.assertEqual(report["commandlets"], ["example"])

    def test_check_plugin_temp_checkout_cli_accepts_zip_submission(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            archive = tmp_path / "example.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for path in plugin_dir.rglob("*"):
                    if path.is_file():
                        zipped.write(path, path.relative_to(tmp_path))

            output = capture_stdout(lambda: main([str(archive), "--temp-checkout", "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertTrue(data["temp_checkout"])
            self.assertEqual(data["plugin"], str(archive))
            self.assertEqual(data["submission"], str(archive))

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_check_plugin_verifies_signed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plugin_dir = write_plugin_fixture(tmp_path, capabilities=())
            private_path, public_path = write_manifest_signing_key(tmp_path)
            with patch("getpass.getpass", return_value="passphrase"):
                self.assertEqual(
                    sign_manifest_main(
                        [
                            "--manifest",
                            str(plugin_dir / "bywaf.plugin.toml"),
                            "--private",
                            str(private_path),
                            "--in-place",
                        ]
                    ),
                    0,
                )

            report = check_plugin(plugin_dir, manifest_key=public_path)

            self.assertTrue(report["ok"])
            self.assertEqual(report["manifest_signature"], "verified")

    def test_check_plugin_verify_requires_manifest_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            report = check_plugin(plugin_dir, verify_manifest=True)

            self.assertFalse(report["ok"])
            self.assertIn("--verify requires --manifest-key", report["errors"])

    def test_check_plugin_text_output(self):
        report = {"ok": False, "plugin": "/tmp/missing", "commandlets": [], "triggers": [], "errors": ["missing"]}

        text = render_text(report)

        self.assertIn("failed plugin=/tmp/missing", text)
        self.assertIn("error: missing", text)

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

    def test_plugin_skeletons_validate(self):
        skeleton_root = Path(__file__).resolve().parents[1] / "docs" / "plugin_skeletons"
        failures: list[str] = []
        for plugin_dir in sorted(path for path in skeleton_root.iterdir() if path.is_dir()):
            if not (plugin_dir / "plugin.py").exists():
                continue
            report = check_plugin(plugin_dir, strict_inference=True)
            if not report["ok"]:
                failures.append(render_text(report))

        self.assertEqual([], failures)

    def test_plugin_skeletons_do_not_drift_to_legacy_api(self):
        skeleton_root = Path(__file__).resolve().parents[1] / "docs" / "plugin_skeletons"
        legacy_tokens = (
            "bywaf.findings",
            "bywaf.finding_grouping",
            "bywaf.finding_taxonomy",
            "bywaf.command_parser",
            "bywaf.command_names",
            "bywaf.plugin_process",
            "BaseCommandlet",
            "info =",
            "def exploit(",
        )
        failures: list[str] = []
        for path in skeleton_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in legacy_tokens:
                if token in text:
                    failures.append(f"{path}: legacy token {token!r}")
            if path.name == "plugin.py":
                plugin_factory = text.split("def plugin", 1)[1] if "def plugin" in text else ""
                if "@commandlet" in plugin_factory:
                    failures.append(f"{path}: @commandlet must not decorate plugin()")

        self.assertEqual([], failures)

    def test_vulnerability_skeletons_keep_split_files_and_finding_helpers(self):
        skeleton_root = Path(__file__).resolve().parents[1] / "docs" / "plugin_skeletons"
        required = {"plugin.py", "command.py", "detect.py", "findings.py", "models.py", "bywaf.plugin.toml"}
        failures: list[str] = []
        for plugin_dir in sorted(path for path in skeleton_root.iterdir() if path.is_dir() and "vulnerability" in path.name):
            present = {path.name for path in plugin_dir.iterdir() if path.is_file()}
            missing = sorted(required - present)
            if missing:
                failures.append(f"{plugin_dir}: missing {', '.join(missing)}")
            findings = plugin_dir.joinpath("findings.py").read_text(encoding="utf-8")
            if "from bywaf.finding import candidate_payload" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing current candidate_payload import")
            if "candidate_payload(" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing candidate_payload usage")
            if "confirmed_payload(" in findings and "from bywaf.finding import candidate_payload, confirmed_payload" not in findings:
                failures.append(f"{plugin_dir}/findings.py: missing confirmed_payload import")

        self.assertEqual([], failures)

    def test_runtime_code_uses_context_for_artifact_store_access(self):
        root = Path(__file__).resolve().parents[1]
        allowed = {
            root / "bywaf" / "artifacts.py",
            root / "bywaf" / "plugin" / "context.py",
            root / "bywaf" / "plugin" / "services.py",
        }
        offenders: list[str] = []
        for path in (root / "bywaf").rglob("*.py"):
            if path in allowed:
                continue
            if "artifact_store_for_event_store" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(root)))

        self.assertEqual([], offenders)

    def test_runtime_artifact_store_access_declares_access_intent(self):
        root = Path(__file__).resolve().parents[1]
        completion_exception = root / "bywaf" / "plugins" / "runtime" / "artifact" / "completion.py"
        offenders: list[str] = []
        for path in (root / "bywaf" / "plugins").rglob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if "context.artifact_store(" not in line:
                    continue
                if "read_access=" in line or "write_access=" in line:
                    continue
                if path == completion_exception:
                    continue
                offenders.append(f"{path.relative_to(root)}:{lineno}")

        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
