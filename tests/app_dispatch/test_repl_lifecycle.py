"""Tests for app repl lifecycle behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch repl lifecycle regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import signal
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    main,
    make_runner,
    read_logical_input,
    repl,
    shutdown_runner,
    confirm_repl_exit,
)
from bywaf.repl.shell import install_shell_suspend_handler, restore_shell_suspend_handler, suspend_to_shell



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app repl lifecycle behavior."""
    def test_main_version_returns_success(self):
        """Protect main version returns success behavior from regressions."""
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--version"]), 0)

    def test_main_direct_unknown_commandlet_returns_error(self):
        """Protect main direct unknown commandlet returns error behavior from regressions."""
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["missing"]), 1)
        self.assertIn("error: unknown commandlet: missing", output.getvalue())

    def test_main_exec_without_command_returns_error(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["exec"]), 1)
        self.assertIn("error: exec requires a command", output.getvalue())

    def test_shutdown_runner_checkpoints_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch.object(runner.db, "checkpoint") as checkpoint:
                shutdown_runner(runner)
            checkpoint.assert_called_once_with()

    def test_repl_checkpoints_on_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("builtins.input", side_effect=["q"]),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                repl(runner)
            checkpoint.assert_called_once_with()

    def test_repl_confirms_keyboard_interrupt_before_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([KeyboardInterrupt, "n", "q"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is KeyboardInterrupt:
                    raise KeyboardInterrupt
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_exits_after_confirmed_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([KeyboardInterrupt, "yes"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is KeyboardInterrupt:
                    raise KeyboardInterrupt
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_confirms_eof_before_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([EOFError, "n", "q"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is EOFError:
                    raise EOFError
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_repl_exits_after_confirmed_eof(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            answers = iter([EOFError, "yes"])

            def reader(prompt=""):
                print(prompt, end="")
                answer = next(answers)
                if answer is EOFError:
                    raise EOFError
                return answer

            with (
                patch("builtins.input", side_effect=reader),
                patch.object(runner.db, "checkpoint") as checkpoint,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                repl(runner)
            checkpoint.assert_called_once_with()
            self.assertIn("Quit Bywaf?", output.getvalue())

    def test_confirm_repl_exit_reprompts_until_yes_or_no(self):
        answers = iter(["maybe", "Y"])

        def reader(prompt):
            print(prompt, end="")
            return next(answers)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(reader))
        self.assertIn("please answer yes or no", output.getvalue())

    def test_confirm_repl_exit_accepts_single_yes_keypress(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(key_reader=lambda: "y"))
        self.assertIn("Quit Bywaf? [y/N] y", output.getvalue())

    def test_confirm_repl_exit_accepts_single_no_keypress(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(confirm_repl_exit(key_reader=lambda: "n"))
        self.assertIn("Quit Bywaf? [y/N] n", output.getvalue())

    def test_confirm_repl_exit_reprompts_single_keypress_until_yes_or_no(self):
        answers = iter(["x", "y"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(confirm_repl_exit(key_reader=lambda: next(answers)))
        self.assertIn("please press y or n", output.getvalue())

    def test_shell_suspend_handler_announces_and_suspends_process_group(self):
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            patch("bywaf.repl.shell.os.getpgrp", return_value=4321),
            patch("bywaf.repl.shell.os.killpg") as killpg,
            patch("bywaf.repl.shell.os.kill") as kill,
            patch("bywaf.repl.shell.signal.signal") as signal_handler,
        ):
            suspend_to_shell(20, None)

        self.assertIn('Dropping to shell; enter "fg" to resume.', output.getvalue())
        killpg.assert_called_once_with(4321, 20)
        kill.assert_not_called()
        self.assertEqual(signal_handler.call_args_list[0].args[1], signal.SIG_DFL)
        self.assertEqual(signal_handler.call_args_list[1].args[1], suspend_to_shell)

    def test_shell_suspend_handler_installs_only_for_interactive_tty(self):
        with (
            patch("bywaf.repl.shell.sys.stdin.isatty", return_value=True),
            patch("bywaf.repl.shell.sys.stdout.isatty", return_value=True),
            patch("bywaf.repl.shell.signal.signal", return_value="old") as signal_handler,
        ):
            handler = install_shell_suspend_handler()
            self.assertIsNotNone(handler)
            restore_shell_suspend_handler(handler)

        self.assertEqual(signal_handler.call_args_list[0].args[1], suspend_to_shell)
        self.assertEqual(signal_handler.call_args_list[1].args[1], "old")

    def test_read_logical_input_joins_backslash_continuations(self):
        state = ShellState()
        with patch("builtins.input", side_effect=["hostscanner \\", "127.0.0.1"]):
            self.assertEqual(read_logical_input(state), "hostscanner \n127.0.0.1")


if __name__ == "__main__":
    unittest.main()
