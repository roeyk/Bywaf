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
from pathlib import Path
from unittest.mock import patch

from scripts.plugin_check import check_plugin, main, render_llm_feedback, render_text
from scripts.plugin_manifest_sign import main as sign_manifest_main


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


def write_plugin_fixture(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    manifest_capabilities: tuple[str, ...] | None = None,
    emits: tuple[str, ...] = (),
    manifest_emits: tuple[str, ...] | None = None,
    imports: str = "",
    decorators: str = "",
    parser_import: str = "from bywaf.plugin import CommandSpec\n",
    run_body: str = "        yield {'ok': True}\n",
    manifest_extra: str = "",
) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    capability_text = repr(capabilities)
    emits_text = repr(emits)
    plugin_dir.joinpath("plugin.py").write_text(
        imports +
        parser_import +
        decorators +
        "class Example:\n"
        f"    spec = CommandSpec('example', 'example plugin', emits={emits_text}, capabilities={capability_text})\n"
        "    def run(self, context, args, input_events):\n"
        f"{run_body}"
        "def plugin():\n"
        "    return Example()\n"
    )
    declared = capabilities if manifest_capabilities is None else manifest_capabilities
    manifest_capability_lines = "".join(f'  "{item}",\n' for item in declared)
    declared_emits = emits if manifest_emits is None else manifest_emits
    manifest_emits_text = "emits = [" + ", ".join(f'"{item}"' for item in declared_emits) + "]\n" if declared_emits else ""
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = [\n"
        f"{manifest_capability_lines}"
        "]\n"
        f"{manifest_emits_text}"
        f"{manifest_extra}"
    )
    return plugin_dir


def write_decorated_factory_fixture(root: Path) -> Path:
    plugin_dir = write_plugin_fixture(root, capabilities=())
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec, commandlet\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
        "@commandlet(name='wrong', description='wrong')\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    return plugin_dir


def write_multifile_plugin_fixture(root: Path) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "from .command import run\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield from run()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    plugin_dir.joinpath("command.py").write_text(
        "def run():\n"
        "    yield {'ok': True}\n"
    )
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
    )
    return plugin_dir


def write_manifest_signing_key(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path = tmp_path / "manifest-signing.pem"
    public_path = tmp_path / "manifest-signing.pub.pem"
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def capture_stdout(fn):
    import contextlib
    import io

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = fn()
    self_result = result
    if self_result not in (None, 0):
        raise AssertionError(f"expected successful return code, got {self_result}")
    return output.getvalue()


if __name__ == "__main__":
    unittest.main()
