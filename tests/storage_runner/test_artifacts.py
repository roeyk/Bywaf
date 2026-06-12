# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility.

Coverage focus: storage runner artifacts regression behavior.
"""

from tests.storage_runner.support import *  # noqa: F403,F405

class StorageRunnerArtifactTests(unittest.TestCase):
    """Groups regression coverage for storage runner tests split by responsibility."""
    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_attach_list_save_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            artifact_source = Path(tmp, "snapshot.html")
            artifact_source.write_text("<html>ok</html>")
            output_path = Path(tmp, "exported.html")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(
                    f"artifact attach step=run-1 file={artifact_source} name='Landing page' note=site snapshot"
                )
                process_framework_requests(runner, ShellState())
                runner.execute("artifact list step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute("search name=landing")
                process_framework_requests(runner, ShellState())
                runner.execute("artifact verify step=run-1")
                process_framework_requests(runner, ShellState())
                runner.execute(f"artifact export step=run-1 file={output_path}")
                process_framework_requests(runner, ShellState())
            self.assertEqual(output_path.read_text(), "<html>ok</html>")
            artifacts = artifact_store_for_db(runner.db).list(command_run_id="run-1")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].name, "Landing page")
            self.assertEqual(artifacts[0].note, "site snapshot")
            self.assertTrue(artifact_db_path(db_path).exists())
            attached_events = runner.db.events_for_topic("artifact.attached")
            self.assertEqual(attached_events[0].payload["command_run_id"], "run-1")
            self.assertEqual(attached_events[0].payload["name"], "Landing page")
            self.assertEqual(attached_events[0].payload["sha256"], artifacts[0].sha256)
            self.assertEqual(runner.db.events_for_topic("artifact.exported")[0].payload["file"], str(output_path))

    def test_artifact_show_renders_detail_and_next_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            runner.registry.varstore.set("display/style.command_line", "cyan")
            runner.registry.varstore.set("display/style.hash", "color245")
            source = Path(tmp, "proof.txt")
            source.write_text("proof", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source} name=proof.txt note=evidence")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "artifact show 1")

            text = output.getvalue()
            self.assertIn("Artifact summary", text)
            self.assertIn("name: proof.txt", text)
            self.assertIn("step: run-1", text)
            self.assertIn("note: evidence", text)
            self.assertIn("inspect further with:", text)
            self.assertIn("artifact export artifact=1", text)
            self.assertIn("artifact verify artifact=1", text)
            self.assertIn("Provenance events", text)
            self.assertIn("\x1b[36martifact export artifact=1", text)
            self.assertIn("\x1b[38;5;245m", text)

    def test_artifact_cat_renders_text_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            source = Path(tmp, "proof.txt")
            source.write_text("hello\nworld", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source} name=proof.txt")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "artifact cat 1 limit=5")

            text = output.getvalue()
            self.assertIn("Artifact: 1 proof.txt text/plain size=11", text)
            self.assertIn("Preview: text utf-8, first 5 of 11 bytes", text)
            self.assertIn("hello", text)
            self.assertIn("[truncated after 5 of 11 bytes", text)

    def test_artifact_cat_renders_binary_as_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            source = Path(tmp, "proof.bin")
            source.write_bytes(b"\x00\x01ABC\xff")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source} name=proof.bin")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "artifact cat artifact=1 limit=6")

            text = output.getvalue()
            self.assertIn("Artifact: 1 proof.bin application/octet-stream size=6", text)
            self.assertIn("Preview: binary hex, first 6 of 6 bytes", text)
            self.assertIn("00000000  00 01 41 42 43 ff", text)
            self.assertIn("|..ABC.|", text)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_search_filters_name_note_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = Path(tmp, "snapshot.html")
            second = Path(tmp, "headers.txt")
            first.write_text("<html>ok</html>")
            second.write_text("server: test")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={first} name='Landing page' note=html capture")
                runner.execute(f"artifact attach step=run-1 file={second} name=Headers note=response metadata")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("search step=run-1 name=landing")
                process_framework_requests(runner, ShellState())
                runner.execute("search step=run-1 note=metadata")
                process_framework_requests(runner, ShellState())
                runner.execute("search step=run-1 name=headers")
                process_framework_requests(runner, ShellState())
                runner.execute("artifact search step=run-1 --regexp name='land.*page'")
                process_framework_requests(runner, ShellState())
                runner.execute("search step=run-1 --regexp note=response")
                process_framework_requests(runner, ShellState())
                runner.execute("search step=run-1 content='server: test'")
                process_framework_requests(runner, ShellState())
                runner.execute("search step=run-1 filename=snapshot.html")
                process_framework_requests(runner, ShellState())
                runner.execute("artifact search step=run-1 --regexp filename='headers\\.txt'")
                process_framework_requests(runner, ShellState())
            listing = output.getvalue()
            self.assertEqual(listing.count(" name="), 8)
            self.assertIn("name=Landing page", listing)
            self.assertIn("name=Headers", listing)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_attach_and_select_accept_serials(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            source = Path(tmp, "snapshot.html")
            source.write_text("<html>ok</html>")
            output_path = Path(tmp, "out.html")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach serial=run-1 file={source} name='Landing page'")
                process_framework_requests(runner, ShellState())
            artifact = artifact_store_for_db(runner.db).list(command_run_id="run-1")[0]
            self.assertEqual(artifact.name, "Landing page")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact export serial={artifact.artifact_id} file={output_path}")
                process_framework_requests(runner, ShellState())
            self.assertEqual(output_path.read_text(), "<html>ok</html>")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"search serial={artifact.artifact_id}")
                process_framework_requests(runner, ShellState())
            self.assertIn("Landing page", output.getvalue())

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_import_and_attach_existing_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            source = Path(tmp, "snapshot.html")
            source.write_text("<html>ok</html>")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact import file={source} name='Landing page'")
                process_framework_requests(runner, ShellState())
            imported = artifact_store_for_db(runner.db).list()[0]
            self.assertIsNone(imported.command_run_id)
            self.assertTrue(runner.db.events_for_topic("artifact.imported"))
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach artifact={imported.id} step=run-1")
                process_framework_requests(runner, ShellState())
            attached = artifact_store_for_db(runner.db).list(command_run_id="run-1")[0]
            self.assertEqual(attached.id, imported.id)
            self.assertEqual(attached.name, "Landing page")
            self.assertTrue(runner.db.events_for_topic("artifact.attached"))

    def test_artifact_list_filters_by_topic_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            source = Path(tmp, "snapshot.html")
            source.write_text("<html>ok</html>")
            runner = make_runner(db_path)
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact import file={source} name='Imported page'")
                process_framework_requests(runner, ShellState())
            context = CommandContext(runner.db, source="artifact")
            imported = select_artifacts(context, {"topic": ["artifact.imported"]})
            attached = select_artifacts(context, {"topic": ["artifact.attached"]})

            self.assertEqual([artifact.name for artifact in imported], ["Imported page"])
            self.assertEqual(attached, [])

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_attach_rejects_artifact_parent_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = Path(tmp, "first.txt")
            second = Path(tmp, "second.txt")
            first.write_text("one")
            second.write_text("two")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={first}")
            artifact = artifact_store_for_db(runner.db).list(command_run_id="run-1")[0]
            with self.assertRaisesRegex(ValueError, "artifacts are not attached to other artifacts"):
                runner.execute(f"artifact attach serial={artifact.artifact_id} file={second}")

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_regexp_rejects_invalid_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            source = Path(tmp, "snapshot.html")
            source.write_text("<html>ok</html>")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source} name='Landing page'")
            with self.assertRaisesRegex(ValueError, "invalid search --regexp pattern"):
                runner.execute("search --regexp name='['")

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_save_file_rejects_multiple_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = Path(tmp, "first.txt")
            second = Path(tmp, "second.txt")
            first.write_text("one")
            second.write_text("two")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={first} file={second}")
        with self.assertRaisesRegex(ValueError, "matched multiple artifacts"):
            runner.execute(f"artifact export step=run-1 file={Path(tmp, 'out.txt')}")

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_replace_and_remove_are_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            first = Path(tmp, "first.txt")
            second = Path(tmp, "second.txt")
            first.write_text("one")
            second.write_text("two")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={first}")
            artifact = artifact_store_for_db(runner.db).list(command_run_id="run-1")[0]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"artifact replace artifact={artifact.id} file={second}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"artifact verify artifact={artifact.id}")
                process_framework_requests(runner, ShellState())
                runner.execute(f"artifact remove artifact={artifact.id}")
                process_framework_requests(runner, ShellState())
            self.assertIn("ok artifact=", output.getvalue())
            self.assertIn("removed artifact=", output.getvalue())
            self.assertEqual(artifact_store_for_db(runner.db).list(command_run_id="run-1"), [])
            self.assertTrue(runner.db.events_for_topic("artifact.replaced"))
            self.assertTrue(runner.db.events_for_topic("artifact.removed"))

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_artifact_verify_detects_main_db_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            source = Path(tmp, "snapshot.html")
            source.write_text("<html>ok</html>")
            runner = make_runner(db_path, encrypted=True, passphrase="secret")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source}")
            event = runner.db.events_for_topic("artifact.attached")[0]
            payload = dict(event.payload)
            payload["sha256"] = "bad"
            with runner.db.connect() as conn:
                conn.execute(
                    "UPDATE events SET payload_json = ? WHERE id = ?",
                    (json.dumps(payload, sort_keys=True), event.id),
                )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("artifact verify step=run-1")
                process_framework_requests(runner, ShellState())
            self.assertIn("main-db sha256 mismatch", output.getvalue())

    def test_artifact_attach_uses_plaintext_store_for_plaintext_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "note.txt")
            source.write_text("secret")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source}")
            artifacts = artifact_store_for_db(runner.db).list(command_run_id="run-1")
            self.assertEqual(artifacts[0].body, b"secret")
            self.assertTrue(artifact_db_path(runner.db.path).exists())
