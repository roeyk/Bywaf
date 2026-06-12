# ruff: noqa: F403,F405
"""Resources/history/config tests split by responsibility.

Coverage focus: resources history config config preferences regression behavior.
"""

from tests.resources_history_config.support import *  # noqa: F403,F405
class ResourcesHistoryConfigPreferenceTests(unittest.TestCase):
    """Groups regression coverage for resources/history/config tests split by responsibility."""
    def test_regression_script_smoke_variables(self):
        """Protect regression script smoke variables behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            script = Path(__file__).parents[1] / "scripts" / "smoke_variables.bywaf"
            output = io.StringIO()
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover,
                contextlib.redirect_stdout(output),
            ):
                dispatch_repl_line(runner, f"script load file={script}")
            discover.assert_called_once_with("127.0.0.1", "-sn")
            self.assertIn("script variable expansion", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("framework.variable.expanded")[0].payload["variables"], ["discovery/hostscanner.targets"])

    def test_save_and_load_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            config = Path(tmp, "vars.toml")
            dispatch_repl_line(runner, "set test.value=before")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config save file={config}")
            dispatch_repl_line(runner, "set test.value=after")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config load file={config}")
            self.assertEqual(runner.registry.varstore.get("test.value"), "before")
            self.assertIn("[variables]", config.read_text())

    def test_save_config_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            default_config = Path(tmp, "default.toml")
            dispatch_repl_line(runner, "set test.value=default")
            with (
                patch("bywaf.repl.command.resources.DEFAULT_CONFIG", default_config),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "config save file=")
            self.assertIn('"test.value" = "default"', default_config.read_text())

    def test_load_config_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            default_config = Path(tmp, "default.toml")
            default_config.write_text("[variables]\n\"test.value\" = \"default\"\n", encoding="utf-8")
            with (
                patch("bywaf.repl.command.resources.DEFAULT_CONFIG", default_config),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "config load file=")
            self.assertEqual(runner.registry.varstore.get("test.value"), "default")

    def test_load_legacy_json_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            config = Path(tmp, "vars.json")
            config.write_text('{"test.value": "legacy"}\n')
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config load file={config}")
            self.assertEqual(runner.registry.varstore.get("test.value"), "legacy")

    def test_config_theme_loads_named_preset(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, "config theme name=classic")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "cyan")
            self.assertEqual(runner.registry.varstore.get("display/style.string"), "bold yellow")

    def test_config_theme_loads_file_without_replacing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "theme.toml")
            theme.write_text(
                '[variables]\n"display/style.variable" = "bright-cyan"\n"display.expansion" = "changed"\n',
                encoding="utf-8",
            )
            runner.registry.varstore.set("test.value", "kept")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "bright-cyan")
            self.assertEqual(runner.registry.varstore.get("display.expansion"), "changed")
            self.assertEqual(runner.registry.varstore.get("test.value"), "kept")

    def test_config_theme_accepts_structured_foreground_background_styles(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "theme.toml")
            theme.write_text(
                """
[variables."display/style.host"]
foreground = "cyan"
background = "transparent"
bold = true

[variables."display/style.finding.severity_class.emergency"]
foreground = "white"
background = "ansi:52"
bold = true
""",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertEqual(runner.registry.varstore.get("display/style.host"), "bold cyan")
            self.assertEqual(
                runner.registry.varstore.get("display/style.finding.severity_class.emergency"),
                "bold white bg:ansi:52",
            )

    def test_subject_style_accepts_direct_structured_variables(self):
        values = {
            "display/style.host.bold": "true",
            "display/style.host.foreground": "cyan",
            "display/style.host.background": "transparent",
            "display/style.finding.severity_class.emergency.foreground": "white",
            "display/style.finding.severity_class.emergency.background": "ansi:52",
        }

        self.assertEqual(subject_style(values.get, "host"), "bold cyan")
        self.assertEqual(subject_style(values.get, "finding.severity_class.emergency"), "white bg:ansi:52")

    def test_config_theme_rejects_non_display_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            theme = Path(tmp, "bad-theme.toml")
            theme.write_text('[variables]\n"network/portscanner.host" = "127.0.0.1"\n', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"config theme file={theme}")
            self.assertIn("theme variable must start with display.", output.getvalue())

    def test_pref_set_saves_and_applies_user_preference(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref set display.expansion=changed file={prefs}")
            self.assertEqual(runner.registry.varstore.get("display.expansion"), "changed")
            self.assertIn('"display.expansion" = "changed"', prefs.read_text())

    def test_pref_theme_saves_and_applies_named_theme(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref theme=classic file={prefs}")
            self.assertEqual(runner.registry.varstore.get("display/style.variable"), "cyan")
            self.assertIn('"theme" = "classic"', prefs.read_text())

            other = make_runner(Path(tmp, "other.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(other, f"pref load file={prefs}")
            self.assertEqual(other.registry.varstore.get("display/style.variable"), "cyan")

    def test_pref_theme_lists_available_themes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "pref theme")
            self.assertIn("themes: classic, default, mono", output.getvalue())

    def test_startup_preferences_create_default_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "home", ".bywaf", "preferences.toml")
            with patch("bywaf.repl.preferences.DEFAULT_PREFERENCES", prefs):
                apply_startup_preferences(runner, state)
            self.assertTrue(prefs.exists())
            self.assertEqual(prefs.read_text(encoding="utf-8"), "[preferences]\n")

    def test_pref_prompt_pattern_applies_to_shell_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref set prompt.pattern='test> ' file={prefs}", state)
            self.assertEqual(state.prompt_pattern, "test> ")
            self.assertIn('"prompt.pattern" = "test> "', prefs.read_text())

    def test_pref_prompt_short_form_persists_prompt_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            state = ShellState()
            prefs = Path(tmp, "preferences.toml")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"pref prompt '$u@$h> ' file={prefs}", state)
            self.assertEqual(state.prompt_pattern, "$u@$h> ")
            self.assertIn('"prompt.pattern" = "$u@$h> "', prefs.read_text())

    def test_pref_rejects_scanner_variables_but_allows_credential_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            prefs = Path(tmp, "preferences.toml")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"pref set network/portscanner.host=127.0.0.1 file={prefs}")
                dispatch_repl_line(runner, f"pref set mail.smtp.password=secret file={prefs}")
            self.assertIn("not a preference key", output.getvalue())
            self.assertEqual(runner.registry.varstore.get("mail.smtp.password"), "secret")

    def test_save_and_load_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("custom.topic", {"ok": True}, "test")
            saved = Path(tmp, "saved.sqlite3")
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(runner, f"db export file={saved}")
            other = make_runner(Path(tmp, "other.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                dispatch_repl_line(other, f"db load file={saved} --force")
            self.assertEqual(other.db.path, saved)
            self.assertIn("custom.topic", other.db.topics())

    def test_save_history_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = ShellState(session_history=["help  # 2026-05-21 12:00:00 EDT"])
            default_history = Path(tmp, "history.bywaf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.command.resources.DEFAULT_HISTORY", default_history),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "history save file=", state)
            self.assertIn("help", default_history.read_text())

    def test_load_history_empty_value_uses_default_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            default_history = Path(tmp, "history.bywaf")
            default_history.write_text("help  # 2026-05-21 12:00:00 EDT\n", encoding="utf-8")
            state = ShellState()
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.repl.command.resources.DEFAULT_HISTORY", default_history),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                dispatch_repl_line(runner, "history load file=", state)
            self.assertEqual(state.session_history, ["help  # 2026-05-21 12:00:00 EDT"])
