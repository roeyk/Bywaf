"""Tests for completion regression behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: completion regression regression behavior.
- maintainers: document expected behavior through executable examples."""

import os
import importlib
import tempfile
import unittest
from pathlib import Path

from bywaf.completion import BywafPromptLexer, Completer, PromptToolkitCompleter, completion_results, option_is_binary
from bywaf.db import EventStore
from bywaf.registry import PluginRegistry
from bywaf.secret.input import PromptSecretInputState


class CompletionRegressionTests(unittest.TestCase):
    """Groups regression coverage for completion regression behavior."""
    def setUp(self):
        """Prepare shared fixtures for this test case."""
        self.registry = PluginRegistry.discover()
        self.completer = Completer(self.registry)

    def test_every_commandlet_name_is_top_level_completable(self):
        for name in self.registry.names():
            with self.subTest(commandlet=name):
                prefix = name[: max(1, min(4, len(name) - 1))]
                self.assertIn(name, self.completer.candidates(prefix))

    def test_binary_declared_options_complete_as_flags(self):
        for name, plugin in self.registry.plugins.items():
            for option in plugin.spec.options:
                if not option_is_binary(option.name):
                    continue
                with self.subTest(commandlet=name, option=option.name):
                    flag_prefix = f"--{option.name[: max(1, min(3, len(option.name) - 1))]}"
                    self.assertIn(f"--{option.name}", self.completer.candidates(f"{name} {flag_prefix}"))

    def test_value_declared_options_complete_as_key_value_arguments(self):
        for name, plugin in self.registry.plugins.items():
            for option in plugin.spec.options:
                if option_is_binary(option.name):
                    continue
                with self.subTest(commandlet=name, option=option.name):
                    key_prefix = option.name[: max(1, min(3, len(option.name) - 1))]
                    self.assertIn(f"{option.name}=", self.completer.candidates(f"{name} {key_prefix}"))

    def test_commandlet_completion_does_not_advertise_undeclared_framework_options(self):
        for name in self.registry.plugins:
            with self.subTest(commandlet=name):
                candidates = self.completer.candidates(f"{name} --")
                self.assertNotIn("--help", candidates)
                self.assertNotIn("--from", candidates)

    def test_declared_choice_options_complete_key_value_values(self):
        for name, plugin in self.registry.plugins.items():
            for option in plugin.spec.options:
                if not option.choices or option_is_binary(option.name):
                    continue
                with self.subTest(commandlet=name, option=option.name):
                    for choice in option.choices:
                        self.assertIn(f"{option.name}={choice}", self.completer.candidates(f"{name} {option.name}="))

    def test_declared_path_options_complete_key_value_filespec_values(self):
        path_options = [
            (name, option.name)
            for name, plugin in self.registry.plugins.items()
            for option in plugin.spec.options
            if option.completion.kind in {"path", "file", "directory"} and not option_is_binary(option.name)
        ]
        self.assertTrue(path_options)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("")
            Path(tmp, "reports").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                for commandlet, option in path_options:
                    with self.subTest(commandlet=commandlet, option=option):
                        self.assertIn(f"{option}=report.md", completer.candidates(f"{commandlet} {option}=rep"))
            finally:
                os.chdir(cwd)

    def test_explicit_named_arguments_complete_key_value_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completer = Completer(self.registry)
                self.assertIn("export=", completer.candidates("finding_report exp"))
                self.assertIn("export=report.md", completer.candidates("finding_report export=rep"))
                self.assertIn("source=auto", completer.candidates("finding_report source="))
            finally:
                os.chdir(cwd)

    def test_variable_expansion_completion_for_filespec_parameters(self):
        registry = PluginRegistry.discover()
        registry.varstore.set("analysis/finding/report/finding_report.report_path", "report.md")
        registry.varstore.set("global.shared_path", "shared.md")
        completer = Completer(registry)
        self.assertIn("export=$report_path", completer.candidates("finding_report export=$rep"))
        self.assertIn("export=$shared_path", completer.candidates("finding_report export=$sha"))
        self.assertIn(
            "export=${analysis/finding/report/finding_report.report_path}",
            completer.candidates("finding_report export=${analysis"),
        )

    def test_common_manual_regression_cases(self):
        cases = (
            ("hostscanner 127.0.0.1 | por", "portscanner"),
            ("finding_report exp", "export="),
            ("artifact search file", "filename="),
            ("events ", "--tail"),
            ("por", "portscanner"),
            ("plugin lo", "load="),
            ("history save ", "file="),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertIn(expected, self.completer.candidates(line))

    def test_runtime_selector_regression_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            cases = (
                ("job ", str(job_id)),
                ("pipeline ", "1"),
                ("event step=", "step=1"),
                ("event pipeline=", "pipeline=1"),
                ("signal serial=", "serial=run-1"),
                ("portscanner --from job=", f"job={job_id}"),
                ("portscanner --from step=", "step=1"),
                ("portscanner --from pipeline=", "pipeline=1"),
                ("portscanner --from topic=", "topic=host.found"),
            )
            for line, expected in cases:
                with self.subTest(line=line):
                    self.assertIn(expected, completer.candidates(line))

    def test_filespec_parameter_completion_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".bywaf" / "plugins" / "plugin_dir").mkdir(parents=True)
            (root / "script.bywaf").write_text("plugins\n")
            (root / "bywaf.sqlite3").write_text("")
            (root / "bywaf.config.toml").write_text("[variables]\n")
            (root / "history.bywaf").write_text("plugins\n")
            (root / "snapshot.html").write_text("<html></html>")
            (root / "artifacts").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(root)
                completer = Completer(self.registry)
                cases = (
                    ("plugin load=plug", "load=plugin_dir/"),
                    ("script load file=scr", "file=script.bywaf"),
                    ("db load file=byw", "file=bywaf.sqlite3"),
                    ("config load file=byw", "file=bywaf.config.toml"),
                    ("config theme name=cl", "name=classic"),
                    ("pref theme=cl", "theme=classic"),
                    ("pref set identity.em", "identity.email="),
                    ("history load file=his", "file=history.bywaf"),
                    ("db export file=byw", "file=bywaf.sqlite3"),
                    ("config save file=byw", "file=bywaf.config.toml"),
                    ("history save file=his", "file=history.bywaf"),
                    ("artifact attach file=snap", "file=snapshot.html"),
                    ("artifact export dir=art", "dir=artifacts/"),
                    ("finding_report export=snap", "export=snapshot.html"),
                    ("finding_dedupe file=snap", "file=snapshot.html"),
                    ("yara_scan rule=snap", "rule=snapshot.html"),
                    ("hostscanner @scr", "@script.bywaf"),
                    ("hostscanner @lines:scr", "@lines:script.bywaf"),
                    ("hostscanner @@scr", "@@script.bywaf"),
                )
                for line, expected in cases:
                    with self.subTest(line=line):
                        self.assertIn(expected, completer.candidates(line))
            finally:
                os.chdir(cwd)

    def test_double_dash_does_not_duplicate_or_show_named_arguments(self):
        candidates = self.completer.candidates("finding_report --")
        self.assertEqual(candidates, [])
        self.assertNotIn("export=", candidates)
        self.assertNotIn("--", completion_results("finding_report --", candidates))

    def test_prompt_toolkit_key_value_display_hides_key_prefix(self):
        try:
            Document = importlib.import_module("prompt_toolkit.document").Document
        except ImportError:
            self.skipTest("prompt_toolkit is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "report.md").write_text("")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                completions = list(PromptToolkitCompleter(Completer(self.registry)).get_completions(Document("finding_report export=rep"), None))
            finally:
                os.chdir(cwd)
        display_texts = [completion.display_text for completion in completions]
        self.assertIn("report.md", display_texts)
        self.assertNotIn("export=report.md", display_texts)

    def test_prompt_lexer_styles_values_and_quoted_strings(self):
        try:
            Document = importlib.import_module("prompt_toolkit.document").Document
        except ImportError:
            self.skipTest("prompt_toolkit is not installed")
        self.registry.varstore.set("display/style.variable", "cyan")
        self.registry.varstore.set("display/style.value", "green")
        self.registry.varstore.set("display/style.string", "bold yellow")
        lexer = BywafPromptLexer(Completer(self.registry), PromptSecretInputState())
        fragments = lexer.lex_document(Document('set host=127.0.0.1 note="manual $A pass" event port.open host=$A'))(0)

        self.assertIn(("ansicyan", "host"), fragments)
        self.assertIn(("ansigreen", "127.0.0.1"), fragments)
        self.assertIn(("ansicyan", "note"), fragments)
        self.assertIn(("bold ansiyellow", '"manual '), fragments)
        self.assertIn(("ansicyan", "$A"), fragments)
        self.assertIn(("bold ansiyellow", ' pass"'), fragments)
        self.assertIn(("ansicyan", "$A"), fragments)

    def test_prompt_lexer_does_not_style_variables_inside_single_quotes(self):
        try:
            Document = importlib.import_module("prompt_toolkit.document").Document
        except ImportError:
            self.skipTest("prompt_toolkit is not installed")
        self.registry.varstore.set("display/style.variable", "cyan")
        self.registry.varstore.set("display/style.string", "bold yellow")
        lexer = BywafPromptLexer(Completer(self.registry), PromptSecretInputState())
        fragments = lexer.lex_document(Document("set note='literal $A' other=$A"))(0)

        self.assertIn(("bold ansiyellow", "'literal $A'"), fragments)
        self.assertIn(("ansicyan", "$A"), fragments)

if __name__ == "__main__":
    unittest.main()
