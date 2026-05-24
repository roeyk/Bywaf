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
            self.assertEqual(report["commandlets"], ["example"])
            self.assertEqual(report["triggers"], [])
            self.assertEqual(report["errors"], [])

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
            self.assertIn("process.run", report["inferred_capabilities"])
            self.assertIn("process.run", report["missing_capabilities"])
            self.assertEqual(report["errors"], [])
            self.assertEqual(report["evidence"][0]["kind"], "framework_call")

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
                imports="from bywaf.findings import candidate_payload\n",
                run_body="        yield candidate_payload(title='t', classification='wrong', target={})\n",
            )

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "invalid-candidate-payload-keyword")

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


def write_plugin_fixture(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    manifest_capabilities: tuple[str, ...] | None = None,
    imports: str = "",
    decorators: str = "",
    parser_import: str = "from bywaf.plugin import CommandSpec\n",
    run_body: str = "        yield {'ok': True}\n",
) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    capability_text = repr(capabilities)
    plugin_dir.joinpath("plugin.py").write_text(
        imports +
        parser_import +
        decorators +
        "class Example:\n"
        f"    spec = CommandSpec('example', 'example plugin', capabilities={capability_text})\n"
        "    def run(self, context, args, input_events):\n"
        f"{run_body}"
        "def plugin():\n"
        "    return Example()\n"
    )
    declared = capabilities if manifest_capabilities is None else manifest_capabilities
    manifest_capability_lines = "".join(f'  "{item}",\n' for item in declared)
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = [\n"
        f"{manifest_capability_lines}"
        "]\n"
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
