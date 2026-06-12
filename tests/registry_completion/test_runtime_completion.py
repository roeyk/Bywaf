# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility.

Coverage focus: registry completion runtime completion regression behavior.
"""

from tests.registry_completion.support import *  # noqa: F403,F405
class RegistryRuntimeCompletionTests(unittest.TestCase):
    """Groups regression coverage for registry and completion tests split by responsibility."""
    def setUp(self):
        """Prepare shared fixtures for this test case."""
        self.registry = PluginRegistry.discover()

    def test_event_completes_topics_and_jobs(self):
        """Protect event completes topics and jobs behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish("custom.topic", {"ok": True}, "test")
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            candidates = completer.candidates("event ")
            self.assertIn("custom.topic", candidates)
            self.assertIn("job=1", candidates)

    def test_events_completes_tail_selectors(self):
        """Protect events completes tail selectors behavior from regressions."""
        completer = Completer(self.registry)
        self.assertIn("--tail", completer.candidates("events "))
        self.assertNotIn("tail", completer.candidates("events "))
        self.assertIn("last=", completer.candidates("events "))

    def test_job_completes_actions_and_job_ids(self):
        """Protect job completes actions and job ids behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.record_job("hostscanner 127.0.0.1", 123, "running")
            completer = Completer(self.registry, db)
            self.assertIn("cancel", completer.candidates("job "))
            self.assertIn("end", completer.candidates("job e"))
            self.assertIn("kill", completer.candidates("job k"))
            self.assertIn("1", completer.candidates("job "))
            self.assertIn("host=", completer.candidates("job h"))
            self.assertIn("--new", completer.candidates("job --n"))
            self.assertIn("since=", completer.candidates("job si"))
            self.assertIn("sort=", completer.candidates("job s"))
            self.assertIn("sort=started", completer.candidates("job sort=st"))
            self.assertIn("sort=-started", completer.candidates("job sort=-st"))
            self.assertEqual(completer.candidates("job cancel "), ["1"])

    def test_pipeline_and_control_complete_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            db.record_command_run_vars(
                job_id=job_id,
                pipeline_id="pipe-1",
                command_run_id="run-1",
                commandlet="hostscanner",
                values={"test.marker": "1"},
            )
            completer = Completer(self.registry, db)
            self.assertIn("end", completer.candidates("pipeline e"))
            self.assertIn("kill", completer.candidates("pipeline k"))
            self.assertIn("1", completer.candidates("pipeline "))
            self.assertIn("host=", completer.candidates("pipeline h"))
            self.assertIn("--new", completer.candidates("pipeline --n"))
            self.assertIn("since=", completer.candidates("pipeline si"))
            self.assertIn("sort=", completer.candidates("pipeline s"))
            self.assertIn("sort=status", completer.candidates("pipeline sort=st"))
            self.assertIn("sort=-status", completer.candidates("pipeline sort=-st"))
            self.assertIn("host=", completer.candidates("step h"))
            self.assertIn("--new", completer.candidates("step --n"))
            self.assertIn("since=", completer.candidates("step si"))
            self.assertIn("sort=", completer.candidates("step s"))
            self.assertIn("sort=started", completer.candidates("step sort=st"))
            self.assertIn("sort=-started", completer.candidates("step sort=-st"))
            self.assertEqual(completer.candidates("end job="), ["job=1"])
            self.assertEqual(completer.candidates("kill job="), ["job=1"])
            self.assertEqual(completer.candidates("kill pipeline="), ["pipeline=1"])
            self.assertIn("serial=run-1", completer.candidates("signal serial="))
            self.assertIn("serial=pipe-1", completer.candidates("signal serial="))
            self.assertEqual(completer.candidates("cancel pipeline="), ["pipeline=1"])

    def test_project_completes_actions_and_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_root = Path(tmp, ".bywaf", "projects")
            (project_root / "client-a").mkdir(parents=True)
            (project_root / "client-b").mkdir()
            completer = Completer(self.registry)
            with patch("pathlib.Path.home", return_value=Path(tmp)):
                self.assertEqual(completer.candidates("project "), ["archive", "export", "info", "list", "new", "use"])
                self.assertEqual(completer.candidates("project i"), ["info"])
                self.assertEqual(completer.candidates("project new "), ["--encrypt", "name="])
                self.assertEqual(completer.candidates("project use "), ["--force", "name="])
                self.assertEqual(completer.candidates("project use name=client-"), ["name=client-a", "name=client-b"])
                self.assertEqual(completer.candidates("project use c"), ["client-a", "client-b"])
                self.assertEqual(completer.candidates("project use --f"), ["--force"])
        self.assertEqual(completer.candidates("project archive "), ["--encrypt", "file="])

    def test_builtin_commands_do_not_fall_back_to_root_completion(self):
        completer = Completer(self.registry)
        self.assertEqual(completer.candidates("plugins "), [])
        self.assertEqual(completer.candidates("info "), [])
        self.assertEqual(completer.candidates("triggers "), [])
        self.assertEqual(completer.candidates("exit "), [])
        self.assertEqual(completer.candidates("quit "), [])
        self.assertEqual(completer.candidates("q "), [])
        self.assertEqual(completer.candidates("cmds "), ["--page"])
        self.assertEqual(completer.candidates("cmds --"), ["--page"])
        self.assertIn("--all", completer.candidates("job "))
        self.assertIn("--all", completer.candidates("job --a"))
        self.assertIn("--page", completer.candidates("job "))
        self.assertIn("--page", completer.candidates("pipeline "))
        self.assertIn("--all", completer.candidates("pipeline --a"))
        self.assertIn("--page", completer.candidates("pipeline --p"))
        self.assertIn("--all", completer.candidates("step "))
        self.assertIn("--all", completer.candidates("step --a"))
        self.assertIn("plugins", completer.candidates("help plu"))
        self.assertIn("project", completer.candidates("? pro"))

    def test_cancel_completion_menu_dismisses_active_popup(self):
        class Buffer:
            cancelled = False

            def cancel_completion(self):
                self.cancelled = True

        class Event:
            current_buffer = Buffer()

        event = Event()
        cancel_completion_menu(event)
        self.assertTrue(event.current_buffer.cancelled)

    def test_readline_delimiters_keep_hyphen_and_equals_in_completion_word(self):
        with (
            patch("bywaf.completion.readline.get_completer_delims", return_value=" \t\n-="),
            patch("bywaf.completion.readline.set_completer_delims") as set_delims,
        ):
            configure_readline_delimiters()
        set_delims.assert_called_once_with(" \t\n")
