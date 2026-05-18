import os
import importlib
import tempfile
import unittest
from pathlib import Path

from bywaf.completion import Completer, PromptToolkitCompleter, completion_results, option_is_binary
from bywaf.db import EventStore
from bywaf.registry import PluginRegistry


class CompletionRegressionTests(unittest.TestCase):
    def setUp(self):
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
        registry.varstore.set("finding_report.report_path", "report.md")
        registry.varstore.set("global.shared_path", "shared.md")
        completer = Completer(registry)
        self.assertIn("export=$report_path", completer.candidates("finding_report export=$rep"))
        self.assertIn("export=$shared_path", completer.candidates("finding_report export=$sha"))
        self.assertIn("export=${finding_report.report_path}", completer.candidates("finding_report export=${finding"))

    def test_common_manual_regression_cases(self):
        cases = (
            ("hostscanner 127.0.0.1 | por", "portscanner"),
            ("finding_report --", "--help"),
            ("artifact search file", "filename="),
            ("events ", "tail"),
            ("run por", "portscanner"),
            ("load pl", "plugin="),
            ("save hi", "history="),
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
                ("job show ", str(job_id)),
                ("pipeline show ", "1"),
                ("event run=", "run=1"),
                ("event pipeline=", "pipeline=1"),
                ("signal serial=", "serial=run-1"),
                ("portscanner --from-run ", "1"),
                ("portscanner --from-pipeline ", "1"),
                ("portscanner --from-topic ", "host.found"),
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
            (root / "bywaf.config.json").write_text("{}")
            (root / "history.bywaf").write_text("plugins\n")
            (root / "snapshot.html").write_text("<html></html>")
            (root / "artifacts").mkdir()
            cwd = Path.cwd()
            try:
                os.chdir(root)
                completer = Completer(self.registry)
                cases = (
                    ("load plugin=plug", "plugin=plugin_dir/"),
                    ("load script=scr", "script=script.bywaf"),
                    ("load db=byw", "db=bywaf.sqlite3"),
                    ("load config=byw", "config=bywaf.config.json"),
                    ("load history=his", "history=history.bywaf"),
                    ("save db=byw", "db=bywaf.sqlite3"),
                    ("save config=byw", "config=bywaf.config.json"),
                    ("save history=his", "history=history.bywaf"),
                    ("artifact attach file=snap", "file=snapshot.html"),
                    ("artifact save dir=art", "dir=artifacts/"),
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
        self.assertIn("--help", candidates)
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


if __name__ == "__main__":
    unittest.main()
