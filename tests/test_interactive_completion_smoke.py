"""Tests for interactive completion smoke behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

# pyright: reportMissingModuleSource=false


try:
    import pexpect
except ImportError:  # pragma: no cover - depends on developer environment.
    pexpect = None


class InteractiveCompletionSmokeTests(unittest.TestCase):
    def spawn_bywaf(self, cwd: Path) -> Any:
        if pexpect is None:
            self.skipTest("pexpect is not installed")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        env["BYWAF_INPUT_READER"] = "readline"
        return pexpect.spawn(
            "python3",
            ["-m", "bywaf", "--database", str(cwd / "bywaf.sqlite3")],
            cwd=str(cwd),
            env=env,
            encoding="utf-8",
            timeout=5,
        )

    def expect_prompt(self, child) -> None:
        child.expect_exact("bywaf> ")

    def close_repl(self, child) -> None:
        if pexpect is None:
            return
        child.sendcontrol("u")
        child.sendline("exit")
        child.expect(pexpect.EOF)

    def test_tab_completes_command_after_pipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = self.spawn_bywaf(Path(tmp))
            try:
                self.expect_prompt(child)
                child.send("hostscanner 127.0.0.1 | por")
                child.send("\t")
                child.expect_exact("portscanner")
            finally:
                self.close_repl(child)

    def test_tab_completes_filespec_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot.html").write_text("<html></html>")
            child = self.spawn_bywaf(root)
            try:
                self.expect_prompt(child)
                child.send("finding_report export=snap")
                child.send("\t")
                child.expect_exact("export=snapshot.html")
            finally:
                self.close_repl(child)

    def test_double_dash_tab_does_not_duplicate_dash_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = self.spawn_bywaf(Path(tmp))
            try:
                self.expect_prompt(child)
                child.send("finding_report --")
                child.send("\t")
                child.expect_exact("--")
                self.assertNotIn("----", f"{child.before}{child.after}")
            finally:
                self.close_repl(child)

if __name__ == "__main__":
    unittest.main()
