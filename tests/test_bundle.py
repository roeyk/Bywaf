"""Tests for bundle behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, process_framework_requests
from bywaf.keyring import generate_key
from bywaf.command.parser import parse_invocation


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


class BundleTests(unittest.TestCase):
    def test_parse_invocation_preserves_bundle_name_selector(self):
        invocation = parse_invocation("bundle create name=client-a")
        self.assertEqual(invocation.name, "bundle")
        self.assertEqual(invocation.args, ["create", "name=client-a"])
        self.assertIsNone(invocation.display_name)

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_bundle_create_add_seal_verify_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence.txt"
            evidence.write_text("bundle evidence\n", encoding="utf-8")
            export = root / "client-a.bundle.json"
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": str(root / "keys")}):
                generate_key("firm-evidence", "passphrase")
                runner = make_runner(root / "bywaf.sqlite3")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    runner.execute("bundle create name=client-a")
                    runner.execute(f"artifact attach step=1 file={evidence} name=sample note=bundle")
                    runner.execute("bundle add name=client-a audit topic=artifact.attached")
                    runner.execute("bundle add name=client-a evidence commandlet=artifact")
                    with patch("getpass.getpass", return_value="passphrase"):
                        runner.execute("bundle seal name=client-a --sign key=firm-evidence")
                    runner.execute("bundle verify name=client-a")
                    runner.execute(f"bundle export name=client-a file={export}")
                    process_framework_requests(runner, ShellState())

                text = output.getvalue()
                self.assertIn("created bundle name=client-a", text)
                self.assertIn("sealed bundle name=client-a", text)
                self.assertIn("ok bundle name=client-a", text)
                self.assertTrue(export.exists())
                data = json.loads(export.read_text(encoding="utf-8"))
                self.assertEqual(data["format"], "bywaf.bundle.v1")
                self.assertEqual(data["name"], "client-a")
                self.assertEqual(len(data["items"]), 2)
                topics = runner.db.topics()
                self.assertIn("bundle.created", topics)
                self.assertIn("bundle.item.added", topics)
                self.assertIn("bundle.sealed", topics)
                self.assertIn("bundle.exported", topics)

    @unittest.skipUnless(cryptography_available(), "cryptography is not installed")
    def test_sealed_bundle_rejects_new_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": str(root / "keys")}):
                runner = make_runner(root / "bywaf.sqlite3")
                runner.execute("bundle create name=client-a")
                runner.execute("bundle seal name=client-a")

                with self.assertRaisesRegex(ValueError, "bundle is sealed"):
                    runner.execute("bundle add name=client-a audit")
