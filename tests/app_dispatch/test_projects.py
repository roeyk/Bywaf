"""Tests for app projects behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch projects regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from bywaf.artifacts import artifact_store_for_db
from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    extract_startup_project,
    make_runner,
)
from bywaf.projects import ProjectPaths



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app projects behavior."""
    def test_dispatch_list_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "list")
            self.assertIn("error: unknown command or commandlet", output.getvalue())

    def test_dispatch_topics_accepts_prefix_on_empty_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "topics plugins")
            self.assertIn("no matching topics: plugins", output.getvalue())

    def test_dispatch_topics_filters_by_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "test")
            runner.db.publish("port.open", {"port": 80}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "topics host")
            self.assertIn("host.found", output.getvalue())
            self.assertNotIn("port.open", output.getvalue())

    def test_extract_startup_project_peels_project_selector(self):
        project, argv = extract_startup_project(["project=client-a", "--new", "repl"])
        self.assertEqual(project, "client-a")
        self.assertEqual(argv, ["--new", "repl"])
        project, argv = extract_startup_project(["--new", "project=client-b"])
        self.assertEqual(project, "client-b")
        self.assertEqual(argv, ["--new"])

    def test_project_use_refuses_active_jobs_and_mentions_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                runner = make_runner(Path(tmp, "adhoc.sqlite3"))
                state = ShellState()
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "project new name=client-a", state)
                runner.db.record_job("hostscanner 127.0.0.1&", None, "running")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "project use name=client-a", state)
                text = output.getvalue()
                self.assertIn("cannot switch to project=client-a while 1 job(s) are active", text)
                self.assertIn("project use name=client-a --force", text)
                self.assertEqual(runner.db.path, Path(tmp, "adhoc.sqlite3"))

    def test_project_use_force_stops_active_jobs_and_switches_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"HOME": tmp}):
                runner = make_runner(Path(tmp, "adhoc.sqlite3"))
                state = ShellState()
                runner.registry.varstore.set("global.marker", "old")
                with contextlib.redirect_stdout(io.StringIO()):
                    dispatch_repl_line(runner, "project new name=client-a", state)
                old_db = runner.db
                job_id = old_db.record_job("hostscanner 127.0.0.1&", None, "running")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    dispatch_repl_line(runner, "project use name=client-a --force", state)
                self.assertIn("stopped 1 active job(s)", output.getvalue())
                self.assertIn("using project=client-a", output.getvalue())
                self.assertEqual(runner.db.path, Path(tmp, ".bywaf", "projects", "client-a", "bywaf.sqlite3"))
                self.assertEqual(state.history_path, Path(tmp, ".bywaf", "projects", "client-a", "history.bywaf"))
                self.assertIsNone(runner.registry.varstore.get("global.marker"))
                old_job = old_db.job(job_id)
                assert old_job is not None
                self.assertEqual(old_job["status"], "killed")
                events = old_db.events_for_topic("project.switch.force_stopped")
                self.assertEqual(events[-1].payload["count"], 1)
                self.assertEqual(events[-1].payload["jobs"][0]["job_id"], job_id)

    def test_project_archive_includes_project_state_and_artifact_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_dir = root / ".bywaf" / "projects" / "client-a"
            project_dir.mkdir(parents=True)
            paths = ProjectPaths(
                name="client-a",
                root=root / ".bywaf" / "projects",
                path=project_dir,
                database=project_dir / "bywaf.sqlite3",
                config=project_dir / "config.toml",
                history=project_dir / "history.bywaf",
            )
            paths.config.write_text("[variables]\n", encoding="utf-8")
            paths.history.write_text("set target=127.0.0.1\n", encoding="utf-8")
            runner = make_runner(paths.database, project=paths)
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "test")
            source = project_dir / "artifact.txt"
            source.write_text("artifact body", encoding="utf-8")
            artifact_store_for_db(runner.db).attach_file(source, commandlet="test")

            archive = root / "client-a.zip"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"project archive file={archive}", ShellState())

            self.assertIn("archived project=client-a", output.getvalue())
            self.assertTrue(archive.exists())
            with zipfile.ZipFile(archive) as zipped:
                names = set(zipped.namelist())
                self.assertIn("bywaf.sqlite3", names)
                self.assertIn("bywaf.artifacts.sqlite3", names)
                self.assertIn("config.toml", names)
                self.assertIn("history.bywaf", names)
                manifest = json.loads(zipped.read("bywaf-archive-manifest.json"))
            self.assertEqual(manifest["schema"], "bywaf.project-archive.v1")
            self.assertEqual(manifest["project"], "client-a")
            self.assertEqual({item["path"] for item in manifest["files"]}, names - {"bywaf-archive-manifest.json"})
            events = runner.db.events_for_topic("project.archived")
            self.assertEqual(events[-1].payload["file"], str(archive))

    def test_project_archive_requires_active_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "adhoc.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, f"project archive file={Path(tmp, 'archive.zip')}", ShellState())
            self.assertIn("project archive requires an active project", output.getvalue())


if __name__ == "__main__":
    unittest.main()
