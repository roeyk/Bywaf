"""Tests for the filesystem plugin scaffold command.

Coverage focus: plugin new regression behavior.
"""

from __future__ import annotations

import json
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bywaf.registry import PluginRegistry


ROOT = Path(__file__).resolve().parents[1]


class PluginNewTests(unittest.TestCase):
    """Groups regression coverage for the filesystem plugin scaffold command."""
    def test_plugin_new_generates_plugin_that_passes_checker_and_tests(self):
        """Protect plugin new generates plugin that passes checker and tests behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp) / "generated_probe"

            create = run_script(
                "scripts/plugin_new.py",
                "generated_probe",
                "--output",
                str(plugin_dir),
            )

            self.assertEqual(create.returncode, 0, create.stdout + create.stderr)
            self.assertTrue(plugin_dir.joinpath("plugin.py").exists())
            self.assertTrue(plugin_dir.joinpath("bywaf.plugin.toml").exists())
            self.assertTrue(plugin_dir.joinpath("tests", "test_generated_probe.py").exists())
            readme = plugin_dir.joinpath("README.md").read_text(encoding="utf-8")
            self.assertIn("## Where To Put Code", readme)
            self.assertIn("inside `generated_probe(...)` in", readme)
            self.assertIn("Keep `bywaf.plugin.toml` synchronized", readme)

            check = run_script(
                "scripts/plugin_check.py",
                str(plugin_dir),
                "--strict-inference",
                "--json",
            )

            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            report = json.loads(check.stdout)
            self.assertTrue(report["ok"])
            self.assertEqual(report["commandlets"], ["generated_probe"])
            self.assertEqual(report["declared_emits"], ["generated_probe.observed"])

            tests = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(plugin_dir / "tests")],
                cwd=ROOT,
                env=scaffold_env(plugin_dir),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(tests.returncode, 0, tests.stdout + tests.stderr)

    def test_plugin_new_rejects_non_empty_output_directory(self):
        """Protect plugin new rejects non empty output directory behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp) / "existing"
            plugin_dir.mkdir()
            plugin_dir.joinpath("keep.txt").write_text("user data", encoding="utf-8")

            result = run_script(
                "scripts/plugin_new.py",
                "generated_probe",
                "--output",
                str(plugin_dir),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists and is not empty", result.stderr)
            self.assertEqual(plugin_dir.joinpath("keep.txt").read_text(encoding="utf-8"), "user data")

    def test_plugin_new_rejects_invalid_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_script(
                "scripts/plugin_new.py",
                "Bad-Name",
                "--output",
                str(Path(tmp) / "bad"),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("lowercase snake_case", result.stderr)

    def test_plugin_new_quotes_free_text_manifest_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp) / "quote_probe"

            create = run_script(
                "scripts/plugin_new.py",
                "quote_probe",
                "--output",
                str(plugin_dir),
                "--description",
                'Probe "quoted" targets',
                "--plugin-version",
                "0.1.0+local",
            )

            self.assertEqual(create.returncode, 0, create.stdout + create.stderr)
            check = run_script(
                "scripts/plugin_check.py",
                str(plugin_dir),
                "--strict-inference",
                "--json",
            )

            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_plugin_new_generates_bundled_native_package(self):
        family_dir = ROOT / "bywaf" / "plugins" / "scaffoldtest"
        plugin_dir = family_dir / "generated_bundle"
        shutil.rmtree(family_dir, ignore_errors=True)
        try:
            create = run_script(
                "scripts/plugin_new.py",
                "generated_bundle",
                "--bundled",
                "scaffoldtest",
                "--topic",
                "generated.bundle",
            )

            self.assertEqual(create.returncode, 0, create.stdout + create.stderr)
            self.assertTrue(family_dir.joinpath("__init__.py").exists())
            self.assertTrue(plugin_dir.joinpath("__init__.py").exists())
            self.assertTrue(plugin_dir.joinpath("bywaf.plugin.toml").exists())
            self.assertFalse(plugin_dir.joinpath("plugin.py").exists())
            readme = plugin_dir.joinpath("README.md").read_text(encoding="utf-8")
            self.assertIn("## Where To Put Code", readme)
            self.assertIn("inside `generated_bundle(...)` in", readme)
            self.assertIn("Add or update repository tests", readme)
            manifest = plugin_dir.joinpath("bywaf.plugin.toml").read_text(encoding="utf-8")
            self.assertIn('module = "bywaf.plugins.scaffoldtest.generated_bundle"', manifest)
            self.assertIn("Checklist: update bywaf/plugins/plugins.toml", create.stdout)

            importlib.invalidate_caches()
            commandlet = PluginRegistry({}).load_package_entry(
                "bywaf.plugins",
                "scaffoldtest.generated_bundle",
            )

            self.assertEqual(commandlet.spec.name, "generated_bundle")
            self.assertEqual(commandlet.spec.emits, ("generated.bundle",))
            self.assertEqual(commandlet.spec.database_actions, ("write",))
        finally:
            for name in list(sys.modules):
                if name.startswith("bywaf.plugins.scaffoldtest"):
                    sys.modules.pop(name, None)
            shutil.rmtree(family_dir, ignore_errors=True)


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    """Test helper for run script."""
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=scaffold_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def scaffold_env(plugin_dir: Path | None = None) -> dict[str, str]:
    """Test helper for scaffold env."""
    env = os.environ.copy()
    paths = [str(ROOT)]
    if plugin_dir is not None:
        paths.insert(0, str(plugin_dir))
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


if __name__ == "__main__":
    unittest.main()
