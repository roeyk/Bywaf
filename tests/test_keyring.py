"""Tests for keyring behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples.

Coverage focus: keyring regression behavior.
"""

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, process_framework_requests
from bywaf.completion import Completer
from bywaf.keyring import (
    export_public_key,
    generate_key,
    import_public_key,
    key_by_name,
    load_key_records,
    signing_key_names,
    test_key as validate_key,
    verification_key_names,
)
from bywaf.registry import PluginRegistry


def cryptography_available() -> bool:
    """Return whether cryptography-backed signing checks can run."""
    return importlib.util.find_spec("cryptography") is not None


@unittest.skipUnless(cryptography_available(), "cryptography is not installed")
class KeyringTests(unittest.TestCase):
    """Groups regression coverage for keyring behavior."""
    def test_generate_key_writes_encrypted_private_and_public_metadata(self):
        """Protect generate key writes encrypted private and public metadata behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": tmp}):
                record = generate_key("firm-evidence", "passphrase")

                self.assertEqual(record.name, "firm-evidence")
                self.assertEqual(record.signing_state, "locked")
                self.assertIn("firm-evidence", signing_key_names())
                self.assertIn("firm-evidence", verification_key_names())
                self.assertEqual(validate_key("firm-evidence", "passphrase"), "available")
                self.assertTrue(record.private_path)
                assert record.private_path is not None
                self.assertEqual(record.private_path.stat().st_mode & 0o777, 0o600)
                self.assertIn("ENCRYPTED", record.private_path.read_text(encoding="utf-8"))
                self.assertEqual(load_key_records()[0].fingerprint, record.fingerprint)

    def test_export_and_import_public_key_creates_verify_only_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_path = Path(tmp, "exported.pub")
            first_root = Path(tmp, "first")
            second_root = Path(tmp, "second")
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": str(first_root)}):
                generated = generate_key("firm-evidence", "passphrase")
                export_public_key("firm-evidence", export_path)

            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": str(second_root)}):
                imported = import_public_key("reviewer", export_path)

                self.assertEqual(imported.fingerprint, generated.fingerprint)
                self.assertEqual(key_by_name("reviewer").signing_state, "verify-only")
                self.assertEqual(validate_key("reviewer"), "verify-only")

    def test_key_commandlet_generates_audited_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "bywaf.sqlite3")
            key_root = Path(tmp, "keys")
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": str(key_root)}):
                runner = make_runner(db_path)
                prompts = iter(["passphrase", "passphrase"])
                output = io.StringIO()
                with patch("getpass.getpass", side_effect=lambda prompt: next(prompts)):
                    with contextlib.redirect_stdout(output):
                        runner.execute("key generate name=firm-evidence")
                        process_framework_requests(runner, ShellState())

                self.assertIn("generated key name=firm-evidence", output.getvalue())
                events = runner.db.events_for_topic("key.generated")
                self.assertEqual(events[0].payload["name"], "firm-evidence")

    def test_key_name_completion_uses_user_keyring(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"BYWAF_KEY_ROOT": tmp}):
                generate_key("firm-evidence", "passphrase")
                completer = Completer(PluginRegistry.discover())

                self.assertEqual(completer.candidates("key show name=firm"), ["name=firm-evidence"])
