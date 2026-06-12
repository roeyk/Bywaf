"""Tests for setup-specific CLI behavior.

Coverage focus: app dispatch setup regression behavior.
"""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.app import main
from bywaf.keyring import KeyRecord


class SetupCliTests(unittest.TestCase):
    """Groups regression coverage for setup-specific CLI behavior."""
    def test_setup_creates_user_config_default_project_and_audit_event(self):
        """Protect setup creates user config default project and audit event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["--setup"]), 0)

                config = Path(tmp, ".bywaf", "config.toml")
                project = Path(tmp, ".bywaf", "projects", "default")
                database = project / "bywaf.sqlite3"
                self.assertTrue(config.exists())
                self.assertTrue((project / "config.toml").exists())
                self.assertTrue((project / "history.bywaf").exists())
                self.assertTrue(database.exists())
                text = output.getvalue()
                self.assertIn("Bywaf configuration created", text)
                self.assertIn("Default project created", text)

                events = EventStore(database).events_for_topic("setup.completed")
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].payload["project"], "default")

    def test_quiet_setup_suppresses_summary_but_creates_state(self):
        """Protect quiet setup suppresses summary but creates state behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["--setup", "--quiet"]), 0)
                self.assertEqual(output.getvalue(), "")
                self.assertTrue(Path(tmp, ".bywaf", "config.toml").exists())

    def test_interactive_setup_keyboard_interrupt_cancels_without_traceback(self):
        """Protect interactive setup keyboard interrupt cancels without traceback behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=KeyboardInterrupt),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("setup cancelled", output.getvalue())
                self.assertFalse(Path(tmp, ".bywaf", "projects", "default", "bywaf.sqlite3").exists())

    def test_interactive_setup_eof_cancels_without_traceback(self):
        """Protect interactive setup eof cancels without traceback behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=EOFError),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("setup cancelled", output.getvalue())
                self.assertFalse(Path(tmp, ".bywaf", "config.toml").exists())

    def test_interactive_setup_accepts_project_name_and_declines_encryption(self):
        """Protect interactive setup accepts project name and declines encryption behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-a", "n", "n"]),
                ):
                    self.assertEqual(main(["--setup"]), 0)

                project = Path(tmp, ".bywaf", "projects", "client-a")
                self.assertTrue(project.exists())
                self.assertIn("Use `bywaf project=client-a`", output.getvalue())
                events = EventStore(project / "bywaf.sqlite3").events_for_topic("setup.completed")
                self.assertFalse(events[-1].payload["encrypted"])
                self.assertEqual(events[-1].payload["generated_keys"], [])

    def test_interactive_setup_can_request_encrypted_project_database(self):
        calls: list[tuple[Path, str | None]] = []
        published: list[dict[str, object]] = []
        outer = self

        class FakeStore:
            def __init__(self, path: Path, *, passphrase: str | None = None):
                calls.append((path, passphrase))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            def publish(self, topic: str, payload: dict[str, object], source: str):
                outer.assertEqual(topic, "setup.completed")
                outer.assertEqual(source, "framework")
                published.append(payload)

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                with (
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-sec", "y", "n"]),
                    patch("bywaf.setup.sqlcipher_available", return_value=True),
                    patch("bywaf.setup.getpass.getpass", side_effect=["secret-passphrase", "secret-passphrase"]),
                    patch("bywaf.setup.EventStore", FakeStore),
                ):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(main(["--setup"]), 0)

        self.assertEqual(calls[-1][1], "secret-passphrase")
        self.assertEqual(published[-1]["project"], "client-sec")
        self.assertTrue(published[-1]["encrypted"])
        self.assertIn("encrypted SQLCipher", output.getvalue())

    def test_interactive_setup_can_generate_signing_keys(self):
        generated_names: list[str] = []

        def fake_generate_key(name: str, passphrase: str, *, scope: str = "user"):
            generated_names.append(name)
            self.assertEqual(passphrase, "key-passphrase")
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
                    patch("builtins.input", side_effect=["client-keys", "n", "y"]),
                    patch("bywaf.setup.getpass.getpass", side_effect=["key-passphrase", "key-passphrase"]),
                    patch("bywaf.setup.generate_key", side_effect=fake_generate_key),
                ):
                    self.assertEqual(main(["--setup"]), 0)

                self.assertEqual(generated_names, ["bundle-signing"])
                self.assertIn("Generated signing keys: bundle-signing", output.getvalue())
                events = EventStore(Path(tmp, ".bywaf", "projects", "client-keys", "bywaf.sqlite3")).events_for_topic(
                    "setup.keys_configured"
                )
                self.assertEqual(len(events), 1)
                self.assertEqual(
                    [record["name"] for record in events[0].payload["generated_keys"]],
                    ["bundle-signing"],
                )

    def test_interactive_setup_key_generation_failure_does_not_publish_setup_event(self):
        def fail_generate_key(name: str, passphrase: str, *, scope: str = "user"):
            del name, passphrase, scope
            raise RuntimeError("key backend unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp, "BYWAF_KEY_ROOT": str(Path(tmp, "keys"))}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["client-fail", "n", "y"]),
                    patch("bywaf.setup.getpass.getpass", side_effect=["key-passphrase", "key-passphrase"]),
                    patch("bywaf.setup.generate_key", side_effect=fail_generate_key),
                ):
                    self.assertEqual(main(["--setup"]), 1)

                self.assertIn("error: key backend unavailable", output.getvalue())
                database = Path(tmp, ".bywaf", "projects", "client-fail", "bywaf.sqlite3")
                self.assertFalse(database.exists())

    def test_interactive_setup_refuses_to_encrypt_existing_project_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, ".bywaf", "projects", "default")
            project.mkdir(parents=True)
            (project / "bywaf.sqlite3").write_text("existing", encoding="utf-8")
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("bywaf.setup.interactive_stdio", return_value=True),
                    patch("builtins.input", side_effect=["", "y"]),
                ):
                    self.assertEqual(main(["--setup"]), 1)
                self.assertIn("cannot enable encryption during setup because project database already exists", output.getvalue())

    def test_interactive_repl_startup_shows_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=True),
                    patch("sys.stdout.isatty", return_value=True),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["repl"]), 0)
                self.assertIn("No Bywaf configuration found.", output.getvalue())
                self.assertIn("Run `bywaf --setup` to create one, or continue with defaults.", output.getvalue())

    def test_quiet_repl_startup_suppresses_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=True),
                    patch("sys.stdout.isatty", return_value=True),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["--quiet", "repl"]), 0)
                self.assertNotIn("No Bywaf configuration found.", output.getvalue())

    def test_non_interactive_repl_startup_suppresses_first_run_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    patch("sys.stdin.isatty", return_value=False),
                    patch("sys.stdout.isatty", return_value=False),
                    patch("bywaf.app.repl", return_value=None),
                ):
                    self.assertEqual(main(["repl"]), 0)
                self.assertNotIn("No Bywaf configuration found.", output.getvalue())

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
