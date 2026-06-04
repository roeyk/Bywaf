"""Tests for setup-specific CLI behavior."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import main
from bywaf.keyring import KeyRecord


class SetupCliTests(unittest.TestCase):
    def test_hidden_plugin_signing_setup_option_generates_plugin_keys(self):
        generated_names: list[str] = []

        def fake_generate_key(name: str, passphrase: str, *, scope: str = "user"):
            generated_names.append(name)
            self.assertEqual(passphrase, "plugin-passphrase")
            self.assertEqual(scope, "user")
            return KeyRecord(
                name=name,
                scope=scope,
                algorithm="ed25519",
                fingerprint=f"SHA256:{name}",
                public_path=Path("/tmp/keys/public") / f"{name}.pub.pem",
                private_path=Path("/tmp/keys/private") / f"{name}.pem",
            )

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp, "BYWAF_KEY_ROOT": str(Path(tmp, "keys"))}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["plugin-publisher", "n", "n", "y"]),
                    patch("bywaf.setup.getpass.getpass", side_effect=["plugin-passphrase", "plugin-passphrase"]),
                    patch("bywaf.setup.generate_key", side_effect=fake_generate_key),
                ):
                    self.assertEqual(main(["--setup", "--setup-plugin-signing-keys"]), 0)

        self.assertEqual(generated_names, ["plugin-manifest-signing", "plugin-catalog-signing"])
        self.assertIn("Generated signing keys: plugin-manifest-signing, plugin-catalog-signing", output.getvalue())


if __name__ == "__main__":
    unittest.main()
