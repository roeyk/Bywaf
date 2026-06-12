"""Tests for user flows behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class UserFlowTests(unittest.TestCase):
    """Groups regression coverage for user flows behavior."""
    def test_user_flow_scripts_pass(self):
        root = Path(__file__).resolve().parents[1]
        runner = root / "tests" / "scripts" / "run_user_flow.py"
        flows = sorted((root / "tests" / "user_flows").glob("*.bywaf"))
        self.assertGreaterEqual(len(flows), 2)
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            env["BYWAF_KEY_ROOT"] = str(Path(tmp, "keys"))
            for index, flow in enumerate(flows):
                with self.subTest(flow=flow.name):
                    database = Path(tmp, f"flow-{index}.sqlite3")
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(runner),
                            str(flow),
                            "--database",
                            str(database),
                            "--tmp",
                            str(Path(tmp, flow.stem)),
                        ],
                        cwd=root,
                        env=env,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
