"""Tests for app vars behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    make_runner,
)
from bywaf.secret.askpass import AskpassUnavailable



class AppDispatchTests(unittest.TestCase):
    def test_use_context_scopes_short_vars_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "set targets=127.0.0.1", state)
                dispatch_repl_line(runner, "use global", state)
                dispatch_repl_line(runner, "set target=global", state)
            self.assertEqual(runner.registry.varstore.get("discovery/hostscanner.targets"), "127.0.0.1")
            self.assertEqual(runner.registry.varstore.get("target"), "global")

    def test_set_lists_active_context_vars_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "getpass")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set zeta=last", state)
                dispatch_repl_line(runner, "set aardvark=first", state)
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "set beta=2", state)
                dispatch_repl_line(runner, "set alpha=1", state)
                dispatch_repl_line(runner, "set", state)
            text = output.getvalue()
            variables_index = text.index("Variables:")
            active_index = text.index("In-focus variables (discovery/hostscanner):")
            self.assertLess(variables_index, active_index)
            self.assertLess(text.index("aardvark=first"), text.index("zeta=last"))
            self.assertLess(
                text.index("discovery/hostscanner.alpha=1"),
                text.index("discovery/hostscanner.beta=2"),
            )
            self.assertGreater(text.index("discovery/hostscanner.alpha=1"), active_index)

    def test_vars_name_prints_one_variable_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "getpass")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set global.proxy=http://127.0.0.1:8080", state)
                dispatch_repl_line(runner, "set global.proxy", state)
                dispatch_repl_line(runner, "use hostscanner", state)
                dispatch_repl_line(runner, "set targets=127.0.0.1", state)
                dispatch_repl_line(runner, "set targets", state)
                dispatch_repl_line(runner, "set missing", state)
            text = output.getvalue()
            self.assertIn("global.proxy=http://127.0.0.1:8080", text)
            self.assertIn("discovery/hostscanner.targets=127.0.0.1", text)
            self.assertIn("error: variable not set: discovery/hostscanner.missing", text)

    def test_setg_sets_global_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "setg proxy=http://127.0.0.1:8080", ShellState())
                dispatch_repl_line(runner, "setg proxy", ShellState())
            self.assertEqual(runner.registry.varstore.get("global.proxy"), "http://127.0.0.1:8080")
            self.assertIn("global.proxy=http://127.0.0.1:8080", output.getvalue())

    def test_pending_catalog_variable_warns_and_survives_default_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set scanners/example.answer=99", ShellState())
            self.assertEqual(runner.registry.varstore.get("scanners/example.answer"), "99")
            self.assertIn(
                "warning: scanners/example is not loaded; storing scanners/example.answer until that commandlet is loaded",
                output.getvalue(),
            )

    def test_vars_plain_password_assignment_is_not_implicitly_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set password=supersecret", state)
                dispatch_repl_line(runner, "set password", state)
            text = output.getvalue()
            self.assertEqual(runner.registry.varstore.get("password"), "supersecret")
            self.assertIn("password=supersecret", text)

    def test_vars_command_name_is_not_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "vars password=supersecret", ShellState())
            self.assertIn("error: unknown command or commandlet", output.getvalue())
            self.assertNotIn("password=supersecret", output.getvalue())
            self.assertIsNone(runner.registry.varstore.get("password"))

    def test_vars_explicit_secret_assignment_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret session.ticket=supersecret", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_trailing_secret_flag_marks_assignment_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set session.ticket=supersecret --secret", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "supersecret")
            self.assertNotIn("supersecret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_secret_equals_flag_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set session.ticket --secret=supersecret", ShellState())
            self.assertIsNone(runner.registry.varstore.get("session.ticket"))
            self.assertIn("usage: set [--secret] name=value", output.getvalue())

    def test_vars_empty_explicit_secret_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "getpass")
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret pw=", state)
                dispatch_repl_line(runner, "set pw", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for pw: ")
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("pw=[REDACTED#", text)

    def test_vars_empty_explicit_secret_uses_askpass_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "askpass")
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.read_askpass_secret", return_value="askpass-secret") as askpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret pw=", state)
                dispatch_repl_line(runner, "set pw", state)
            text = output.getvalue()
            askpass.assert_called_once_with("Secret for pw: ")
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "askpass-secret")
            self.assertNotIn("askpass-secret", text)
            self.assertIn("pw=[REDACTED#", text)

    def test_vars_askpass_failure_warns_and_falls_back_to_getpass(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "askpass")
            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.read_askpass_secret", side_effect=AskpassUnavailable("no gui")),
                patch("bywaf.repl.command.var_secrets.getpass.getpass", return_value="fallback-secret") as getpass,
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                dispatch_repl_line(runner, "set --secret pw=", state)
                dispatch_repl_line(runner, "set pw", state)
            getpass.assert_called_once_with("Secret for pw: ")
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertEqual(runner.registry.secrets.get(stored), "fallback-secret")
            self.assertNotIn("fallback-secret", output.getvalue())
            self.assertIn("askpass secret input unavailable", errors.getvalue())

    def test_vars_unknown_secret_input_mode_warns_and_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "typo")
            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.effective_secret_input_mode", return_value="block"),
                patch("bywaf.repl.command.var_secrets.getpass.getpass", return_value="fallback-secret") as getpass,
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                dispatch_repl_line(runner, "set --secret pw=", state)
                dispatch_repl_line(runner, "set pw", state)
            getpass.assert_called_once_with("Secret for pw: ")
            self.assertIn("unsupported input mode; falling back to auto", errors.getvalue())
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertEqual(runner.registry.secrets.get(stored), "fallback-secret")

    def test_vars_redacted_block_uses_hidden_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState(secret_values={"pw": "block-secret"})
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.getpass.getpass") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret pw=[REDACTED]", state)
                dispatch_repl_line(runner, "set pw", state)
            getpass.assert_not_called()
            text = output.getvalue()
            stored = runner.registry.varstore.get("pw")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "block-secret")
            self.assertNotIn("block-secret", text)
            self.assertIn("pw=[REDACTED#", text)

    def test_vars_empty_trailing_secret_flag_prompts_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("secret.input-mode", "getpass")
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                patch("bywaf.repl.command.var_secrets.getpass.getpass", return_value="prompted-secret") as getpass,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set session.ticket= --secret", state)
                dispatch_repl_line(runner, "set session.ticket", state)
            text = output.getvalue()
            getpass.assert_called_once_with("Secret for session.ticket: ")
            stored = runner.registry.varstore.get("session.ticket")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))
            self.assertEqual(runner.registry.secrets.get(stored), "prompted-secret")
            self.assertNotIn("prompted-secret", text)
            self.assertIn("session.ticket=[REDACTED#", text)

    def test_vars_can_color_names_and_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "yellow")
            runner.registry.varstore.set("display.vars.value-color", "bright-blue")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
                dispatch_repl_line(runner, "set target", state)
            self.assertIn("\x1b[33mtarget\x1b[0m=\x1b[94m127.0.0.1\x1b[0m", output.getvalue())

    def test_vars_accept_extended_color_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "rgb:80,180,90")
            runner.registry.varstore.set("display.vars.value-color", "ansi:34")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
            self.assertIn("\x1b[38;2;80;180;90mtarget\x1b[0m=\x1b[38;5;34m127.0.0.1\x1b[0m", output.getvalue())

    def test_vars_ignore_invalid_extended_color_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            runner.registry.varstore.set("display.vars.name-color", "rgb:999,0,0")
            runner.registry.varstore.set("display.vars.value-color", "ansi:999")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "set target=127.0.0.1", state)
                dispatch_repl_line(runner, "set target", state)
            self.assertIn("target=127.0.0.1", output.getvalue())
            self.assertNotIn("\x1b[", output.getvalue())

    def test_vars_secret_redaction_uses_warning_style_when_colored(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            runner.registry.varstore.set("display.vars.color", "always")
            output = io.StringIO()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, "set --secret session.ticket=supersecret", state)
            self.assertIn("\x1b[37;48;5;52m[REDACTED#", output.getvalue())
            self.assertNotIn("supersecret", output.getvalue())

    def test_vars_secret_assignment_respects_active_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "use ssh_probe", state)
                dispatch_repl_line(runner, "set --secret password=supersecret", state)
            stored = runner.registry.varstore.get("network/ssh_probe.password")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(runner.registry.secrets.is_ref(stored))

    def test_vars_secret_assignment_persists_and_hydrates_from_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = make_runner(db_path)
            with (
                patch("bywaf.repl.command.vars.load_fingerprint_key", return_value=b"k" * 32),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(first, "set --secret ssh_probe.password=supersecret", ShellState())

            second = make_runner(db_path)
            stored = second.registry.varstore.get("network/ssh_probe.password")
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertTrue(second.registry.secrets.is_ref(stored))
            self.assertEqual(second.registry.secrets.get(stored), "supersecret")


if __name__ == "__main__":
    unittest.main()
