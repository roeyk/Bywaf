"""Tests for plugin catalog smoke behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


class PluginCatalogSmokeTests(unittest.TestCase):
    """Groups regression coverage for plugin catalog smoke behavior."""
    @unittest.skipUnless(importlib.util.find_spec("cryptography") is not None, "cryptography is not installed")
    def test_plugin_catalog_signing_cli_smoke_script_passes(self):
        root = Path(__file__).resolve().parents[1]
        script = root / "tests" / "scripts" / "smoke_plugin_catalog_signing.py"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)

        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("plugin catalog signing smoke ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
