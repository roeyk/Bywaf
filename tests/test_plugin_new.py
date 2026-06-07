"""Tests for the filesystem plugin scaffold command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PluginNewTests(unittest.TestCase):
    def test_plugin_new_generates_plugin_that_passes_checker_and_tests(self):
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


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=scaffold_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def scaffold_env(plugin_dir: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    paths = [str(ROOT)]
    if plugin_dir is not None:
        paths.insert(0, str(plugin_dir))
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


if __name__ == "__main__":
    unittest.main()
