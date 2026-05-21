"""Tests for the standalone filesystem plugin checker."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.plugin_check import check_plugin, main, render_text


class PluginCheckTests(unittest.TestCase):
    def test_check_plugin_accepts_valid_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",))

            report = check_plugin(plugin_dir)

            self.assertTrue(report["ok"])
            self.assertEqual(report["commandlets"], ["example"])
            self.assertEqual(report["triggers"], [])
            self.assertEqual(report["errors"], [])

    def test_check_plugin_reports_manifest_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=("network.connect",), manifest_capabilities=())

            report = check_plugin(plugin_dir)

            self.assertFalse(report["ok"])
            self.assertIn("capabilities mismatch", report["errors"][0])

    def test_check_plugin_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = write_plugin_fixture(Path(tmp), capabilities=())

            output = capture_stdout(lambda: main([str(plugin_dir), "--json"]))

            data = json.loads(output)
            self.assertTrue(data["ok"])
            self.assertEqual(data["commandlets"], ["example"])

    def test_check_plugin_text_output(self):
        report = {"ok": False, "plugin": "/tmp/missing", "commandlets": [], "triggers": [], "errors": ["missing"]}

        text = render_text(report)

        self.assertIn("failed plugin=/tmp/missing", text)
        self.assertIn("error: missing", text)


def write_plugin_fixture(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    manifest_capabilities: tuple[str, ...] | None = None,
) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    capability_text = repr(capabilities)
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "class Example:\n"
        f"    spec = CommandSpec('example', 'example plugin', capabilities={capability_text})\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
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
