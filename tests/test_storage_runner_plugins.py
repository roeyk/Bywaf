"""Tests for storage runner plugins behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import json
import os
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    make_runner,
    process_framework_requests,
    parse_save_spec,
)
from bywaf.artifacts import artifact_db_path, artifact_store_for_event_store
from bywaf.db import EventStore, Subscription
from bywaf.db import database_appears_encrypted, sqlcipher_available
from bywaf.plugins.network.nmap_backend import NmapPort
from bywaf.plugins.discovery.hostscanner import HostScanner
from bywaf.plugins.discovery.hostscanner import expand_targets
from bywaf.plugins.network.portscanner import PortScanner
from bywaf.plugins.runtime.artifact import select_artifacts
from bywaf.plugins.runtime.watchdog import Watchdog
from bywaf.plugins.storage.db import encrypt_active_database
from bywaf.plugin import CommandContext
from bywaf.command.parser import parse_invocation, parse_pipeline
from bywaf.runner import expand_at_file_arg, run_background_job
from bywaf.varstore import VarStore



class StorageRunnerPluginTests(unittest.TestCase):
    def test_parse_invocation_uses_first_token_as_name(self):
        invocation = parse_invocation("hostscanner 127.0.0.1")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])

    def test_parse_pipeline(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1 | portscanner port=80 &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertFalse(pipeline.commands[0].background)
        self.assertTrue(pipeline.commands[1].background)

    def test_parse_stage_background_pipeline(self):
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 & | portscanner &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.background for command in pipeline.commands], [True, True])
        self.assertEqual(pipeline.commands[0].args, ["192.168.0.1-2"])

    def test_parse_attached_background_markers(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1& | portscanner&")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertEqual(pipeline.commands[0].args, ["127.0.0.1"])
        self.assertEqual([command.background for command in pipeline.commands], [True, True])

    def test_parse_framework_context_selectors(self):
        invocation = parse_invocation(
            "portscanner --from step=host-run pipeline=pipe job=7 topic=host.found port=80"
        )
        self.assertEqual(invocation.from_step, "host-run")
        self.assertEqual(invocation.from_pipeline, "pipe")
        self.assertEqual(invocation.from_job, "7")
        self.assertEqual(invocation.from_topic, "host.found")
        self.assertEqual(invocation.args, ["port=80"])

    def test_from_selector_requires_replay_scope(self):
        with self.assertRaisesRegex(ValueError, "topic= only narrows"):
            parse_invocation("portscanner --from topic=host.found port=80")

    def test_parse_invocation_strips_final_unquoted_note(self):
        invocation = parse_invocation("hostscanner 127.0.0.1 note=client approved target")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "client approved target")

    def test_parse_invocation_strips_final_unquoted_name(self):
        invocation = parse_invocation("hostscanner 127.0.0.1 name=localhost sweep")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.display_name, "localhost sweep")

    def test_parse_invocation_preserves_plugin_owned_name_selector(self):
        invocation = parse_invocation("key show name=firm-evidence")
        self.assertEqual(invocation.name, "key")
        self.assertEqual(invocation.args, ["show", "name=firm-evidence"])
        self.assertIsNone(invocation.display_name)

    def test_parse_invocation_strips_quoted_note(self):
        invocation = parse_invocation('hostscanner 127.0.0.1 note="client approved target"')
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "client approved target")

    def test_parse_pipeline_keeps_stage_notes_separate(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1 note=scope approved | portscanner note=top ports")
        self.assertEqual(pipeline.commands[0].args, ["127.0.0.1"])
        self.assertEqual(pipeline.commands[0].note, "scope approved")
        self.assertEqual(pipeline.commands[1].args, [])
        self.assertEqual(pipeline.commands[1].note, "top ports")

    def test_parse_pipeline_accepts_name_prefix(self):
        pipeline = parse_pipeline("client subnet scan: hostscanner 127.0.0.1 | portscanner")
        self.assertEqual(pipeline.display_name, "client subnet scan")
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])

    def test_parse_pipeline_does_not_treat_url_colon_as_name(self):
        pipeline = parse_pipeline("http_probe http://127.0.0.1")
        self.assertIsNone(pipeline.display_name)
        self.assertEqual(pipeline.commands[0].args, ["http://127.0.0.1"])

    def test_parse_invocation_keeps_background_marker_with_note(self):
        invocation = parse_invocation("hostscanner 127.0.0.1& note=background scan")
        self.assertTrue(invocation.background)
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "background scan")

    def test_parse_invocation_expands_variables_outside_single_quotes(self):
        store = VarStore()
        store.set("hostscanner.targets", "127.0.0.1 127.0.0.2")
        store.set("global.target", "example.test")
        def scope(name: str) -> str:
            return name

        unquoted = parse_invocation("hostscanner $targets", varstore=store, command_scope_resolver=scope)
        double_quoted = parse_invocation('hostscanner "$targets"', varstore=store, command_scope_resolver=scope)
        single_quoted = parse_invocation("hostscanner '$targets'", varstore=store, command_scope_resolver=scope)
        global_value = parse_invocation("hostscanner $target", varstore=store, command_scope_resolver=scope)
        self.assertEqual(unquoted.args, ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(double_quoted.args, ["127.0.0.1 127.0.0.2"])
        self.assertEqual(single_quoted.args, ["$targets"])
        self.assertEqual(global_value.args, ["example.test"])
        self.assertEqual(unquoted.variable_expansions, ("hostscanner.targets",))
        self.assertEqual(single_quoted.variable_expansions, ())

    def test_parse_invocation_rejects_unknown_variable(self):
        with self.assertRaisesRegex(ValueError, "unknown variable"):
            parse_invocation("hostscanner $missing", varstore=VarStore())

    def test_parse_save_spec_accepts_encrypt_before_resource(self):
        encrypt, resource = parse_save_spec("--encrypt db=client.sqlite3")
        self.assertTrue(encrypt)
        self.assertEqual(resource, "db=client.sqlite3")

    def test_db_commandlet_reports_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("db status")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("mode=plaintext", text)
            self.assertRegex(text, r"events=\d+")
            capabilities = {
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            }
            self.assertIn("db.manage", capabilities)
            self.assertIn("db.raw", capabilities)

    def test_audit_show_prints_matching_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic")
                process_framework_requests(runner, ShellState())
            self.assertIn('"topic": "topic"', output.getvalue())
            self.assertIn('"value": 1', output.getvalue())

    def test_audit_list_capabilities_prints_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "plugin.capability.used",
                {"commandlet": "hostscanner", "capability": "network.connect", "declared": True},
                "hostscanner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list capabilities plugin=hostscanner")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("Capability", text)
            self.assertIn("Range", text)
            self.assertIn("network.connect", text)
            self.assertIn("C400-C499", text)
            self.assertIn("hostscanner", text)
            self.assertIn("observed", text)

    def test_audit_show_filters_since_until_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first = runner.db.publish("topic", {"value": "old"}, "test")
            second = runner.db.publish("topic", {"value": "new"}, "test")
            with runner.db.connect() as conn:
                conn.execute("UPDATE events SET created_at = ? WHERE id = ?", ("2026-05-16T10:00:00+00:00", first.id))
                conn.execute("UPDATE events SET created_at = ? WHERE id = ?", ("2026-05-17T10:00:00+00:00", second.id))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic since=20260517 until=20260517")
                process_framework_requests(runner, ShellState())
            self.assertNotIn('"value": "old"', output.getvalue())
            self.assertIn('"value": "new"', output.getvalue())

    def test_audit_show_filters_since_step_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": "old"}, "test", command_run_id="old-run")
            runner.db.publish("topic", {"value": "new"}, "test", command_run_id="new-run")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic since=step:new-run")
                process_framework_requests(runner, ShellState())
            self.assertNotIn('"value": "old"', output.getvalue())
            self.assertIn('"value": "new"', output.getvalue())

    def test_audit_export_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.jsonl")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path} topic=topic")
                process_framework_requests(runner, ShellState())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["topic"], "topic")
            self.assertEqual(records[0]["payload"]["value"], 1)

    def test_audit_export_writes_sqlite_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.sqlite3")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path}")
                process_framework_requests(runner, ShellState())
            self.assertEqual(EventStore(path).events_for_topic("topic")[0].payload["value"], 1)

    def test_audit_export_writes_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.pdf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path}")
                process_framework_requests(runner, ShellState())
            self.assertTrue(path.read_bytes().startswith(b"%PDF-1.4"))

    def test_audit_export_encrypted_pdf_requires_qpdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.pdf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.runtime.audit.shutil.which", return_value=None),
                patch.dict("sys.modules", {"pikepdf": None}),
            ):
                with self.assertRaisesRegex(ValueError, "qpdf"):
                    runner.execute(f"audit export --encrypt file={path}")

    def test_db_new_file_creates_and_switches_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertGreaterEqual(runner.db.table_counts()["events"], 2)
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested")[0].source, "db")
            self.assertEqual(EventStore(first).events_for_topic("topic")[0].payload["value"], 1)

    def test_db_new_refuses_existing_file_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with self.assertRaisesRegex(ValueError, "already exists"):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, first)
            self.assertEqual(EventStore(second).table_counts()["events"], 1)

    def test_db_new_force_backs_up_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --force --file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertGreaterEqual(runner.db.table_counts()["events"], 2)
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested")[0].source, "db")
            backups = list(Path(tmp).glob("second.sqlite3.bak-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(EventStore(backups[0]).table_counts()["events"], 1)

    def test_db_new_default_path_uses_bywaf_db_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                runner = make_runner(Path("current.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("db new")
                self.assertEqual(runner.db.path.parent, Path(".bywaf/db"))
                self.assertTrue(runner.db.path.name.startswith("bywaf-"))
            finally:
                os.chdir(cwd)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_commandlet_encrypt_decrypts_and_rekeys_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "db.sqlite3")
            runner = make_runner(path)
            runner.db.publish("topic", {"value": 1}, "test")
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                runner.execute("db encrypt")
            self.assertTrue(runner.db.encrypted)
            self.assertTrue(database_appears_encrypted(path))
            self.assertEqual(runner.db.events_for_topic("topic")[0].payload["value"], 1)
            with patch("getpass.getpass", side_effect=["newsecret", "newsecret"]):
                runner.execute("db rekey")
            self.assertEqual(EventStore(path, passphrase="newsecret").table_counts()["events"], 1)
            with patch("builtins.input", return_value="YES"):
                runner.execute("db decrypt")
            self.assertFalse(runner.db.encrypted)
            self.assertFalse(database_appears_encrypted(path))
            self.assertEqual(runner.db.events_for_topic("topic")[0].payload["value"], 1)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_new_encrypt_creates_encrypted_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"db new --encrypt --file={second}")
            self.assertTrue(runner.db.encrypted)
            self.assertTrue(database_appears_encrypted(second))

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_new_uses_encryption_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.registry.varstore.set("db.encryption", "sqlcipher")
            with patch("getpass.getpass", side_effect=["secret", "secret"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"db new --file={second}")
            self.assertTrue(runner.db.encrypted)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_db_encrypt_rejects_background_conversion(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(
                EventStore(Path(tmp, "db.sqlite3")),
                source="db",
                metadata={"background": True},
            )
            with self.assertRaisesRegex(ValueError, "foreground"):
                encrypt_active_database(context)

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
            artifacts = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].name, "Landing page")
            self.assertEqual(artifacts[0].note, "site snapshot")
            self.assertTrue(artifact_db_path(db_path).exists())
            attached_events = runner.db.events_for_topic("artifact.attached")
            self.assertEqual(attached_events[0].payload["command_run_id"], "run-1")
            self.assertEqual(attached_events[0].payload["name"], "Landing page")
            self.assertEqual(attached_events[0].payload["sha256"], artifacts[0].sha256)
            self.assertEqual(runner.db.events_for_topic("artifact.exported")[0].payload["file"], str(output_path))

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
            artifact = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")[0]
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
            imported = artifact_store_for_event_store(runner.db).list()[0]
            self.assertIsNone(imported.command_run_id)
            self.assertTrue(runner.db.events_for_topic("artifact.imported"))
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach artifact={imported.id} step=run-1")
                process_framework_requests(runner, ShellState())
            attached = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")[0]
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
            artifact = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")[0]
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
            artifact = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")[0]
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
            self.assertEqual(artifact_store_for_event_store(runner.db).list(command_run_id="run-1"), [])
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
            artifacts = artifact_store_for_event_store(runner.db).list(command_run_id="run-1")
            self.assertEqual(artifacts[0].body, b"secret")
            self.assertTrue(artifact_db_path(runner.db.path).exists())

    def test_parse_empty_invocation_fails(self):
        with self.assertRaises(ValueError):
            parse_invocation("")

    def test_run_hostscanner_publishes_host_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    events = runner.execute("hostscanner 127.0.0.1")
                    process_framework_requests(runner, ShellState())
            self.assertEqual(events[0].topic, "host.found")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            self.assertEqual(events[0].payload["scanner"], "nmap")
            discover.assert_called_once_with("127.0.0.1", "-sn")
            self.assertIn("hostscanner <", output.getvalue())
            self.assertIn(">: discovered host 127.0.0.1", output.getvalue())
            alerts = runner.db.events_for_topic("console.alert")
            self.assertEqual(alerts[0].payload["message"], "discovered host 127.0.0.1")
            self.assertEqual(alerts[0].payload["source"], "hostscanner")
            capabilities = {
                event.payload["capability"]: event.payload["declared"]
                for event in runner.db.events_for_topic("plugin.capability.used")
                if event.source == "hostscanner"
            }
            self.assertTrue(capabilities["network.connect"])
            self.assertTrue(capabilities["framework.console.alert"])
            self.assertTrue(capabilities["db.write:host.found"])

    def test_hostscanner_uses_targets_variable_when_cli_target_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1")
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            discover.assert_called_once_with("127.0.0.1", "-sn")

    def test_hostscanner_accepts_host_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner host=127.0.0.1")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            discover.assert_called_once_with("127.0.0.1", "-sn")

    def test_framework_expands_and_audits_dollar_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1 127.0.0.2")
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner $targets")
            discover.assert_called_once_with("127.0.0.1 127.0.0.2", "-sn")
            expansions = runner.db.events_for_topic("framework.variable.expanded")
            self.assertEqual(expansions[0].payload["variables"], ["discovery/hostscanner.targets"])
            self.assertEqual(expansions[0].command_run_id, events[0].command_run_id)

    def test_hostscanner_cli_target_overrides_targets_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.0.2.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1")
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.0.2.1")
            discover.assert_called_once_with("192.0.2.1", "-sn")

    def test_framework_note_attaches_to_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 note=client approved target")
            note = runner.db.events_for_topic("note.attached")[0]
            self.assertEqual(note.payload["note"], "client approved target")
            self.assertEqual(note.payload["commandlet"], "hostscanner")
            self.assertEqual(note.command_run_id, events[0].command_run_id)
            self.assertEqual(note.pipeline_id, events[0].pipeline_id)
            self.assertEqual(note.payload["job_id"], runner.db.job()[0]["id"])

    def test_framework_note_attaches_to_each_pipeline_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("127.0.0.1", 80, "tcp", "open", "http")],
                ),
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute(
                        "hostscanner 127.0.0.1 note=scope approved | portscanner note=top ports"
                    )
            notes = runner.db.events_for_topic("note.attached")
            self.assertEqual([note.payload["note"] for note in notes], ["scope approved", "top ports"])
            self.assertEqual(notes[0].command_run_id, events[0].command_run_id)
            self.assertEqual(notes[1].command_run_id, events[-1].command_run_id)

    def test_inline_names_attach_to_pipeline_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("client subnet scan: hostscanner 127.0.0.1 name=localhost sweep")
            names = runner.db.runtime_names()
            pipeline_id = events[0].pipeline_id
            self.assertIsNotNone(pipeline_id)
            assert pipeline_id is not None
            self.assertEqual(names[("pipeline", pipeline_id)], "client subnet scan")
            self.assertEqual(names[("run", events[0].command_run_id or "")], "localhost sweep")

    def test_name_command_assigns_posthoc_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("name step=1 localhost sweep")
                process_framework_requests(runner, ShellState())
                runner.execute("name step=1")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.runtime_names()[("run", "run-1")], "localhost sweep")
            self.assertIn("step=run-1 name=localhost sweep", output.getvalue())

    def test_name_command_accepts_text_keyed_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("name step=run-1 text=localhost sweep")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.runtime_names()[("run", "run-1")], "localhost sweep")

    def test_at_file_lines_expands_before_commandlet_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp, "targets.txt")
            targets.write_text("127.0.0.1\n127.0.0.2\n\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner @lines:{targets}")
            discover.assert_called_once_with("127.0.0.1 127.0.0.2", "-sn")
            expansion = runner.db.events_for_topic("framework.argument.expanded")[0]
            self.assertEqual(expansion.payload["mode"], "lines")
            self.assertEqual(expansion.payload["produced"], 2)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_at_file_expansion_attaches_input_file_when_artifacts_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp, "targets.txt")
            targets.write_text("127.0.0.1\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"), encrypted=True, passphrase="secret")
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner @lines:{targets}")
            expansion = runner.db.events_for_topic("framework.argument.expanded")[0]
            self.assertIn("artifact_id", expansion.payload)
            artifacts = artifact_store_for_event_store(runner.db).list(command_run_id=expansion.command_run_id)
            self.assertEqual(artifacts[0].body, b"127.0.0.1\n")

    def test_at_file_double_at_escapes_literal_at(self):
        values, expansion = expand_at_file_arg("@@literal")
        self.assertEqual(values, ["@literal"])
        self.assertIsNone(expansion)

    def test_at_file_text_expands_as_one_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "value.txt")
            path.write_text("one\ntwo\n")
            values, expansion = expand_at_file_arg(f"@{path}")
        self.assertEqual(values, ["one\ntwo\n"])
        if expansion is None:
            self.fail("expected at-file expansion metadata")
        self.assertEqual(expansion.produced, 1)

    def test_note_command_shows_run_notes_with_timestamp_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 note=client approved target")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note step=1")
                process_framework_requests(runner, ShellState())
            line = output.getvalue().splitlines()[-1]
            self.assertRegex(line, r"^\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("client approved target", line)
            self.assertIn(f"step={events[0].command_run_id}", line)

    def test_note_command_saves_job_notes_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "notes.txt")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 127.0.0.1 note=file export note")
            job_id = runner.db.job()[0]["id"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"note job={job_id} file={path}")
                process_framework_requests(runner, ShellState())
            text = path.read_text()
            self.assertRegex(text, r"^\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("file export note", text)
            self.assertIn(f"saved 1 notes to {path}", output.getvalue())

    def test_note_add_appends_multiple_run_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 127.0.0.1 note=initial note")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("note add step=1 text=second note")
                process_framework_requests(runner, ShellState())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note step=1")
                process_framework_requests(runner, ShellState())
            lines = [line for line in output.getvalue().splitlines() if "step=" in line]
            self.assertEqual(len(lines), 2)
            self.assertIn("initial note", lines[0])
            self.assertIn("second note", lines[1])

    def test_note_add_reads_text_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            note_file = Path(tmp, "note.txt")
            note_file.write_text("file-backed posthoc note\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("manual", None, "finished")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"note add job=1 file={note_file}")
                process_framework_requests(runner, ShellState())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note job=1")
                process_framework_requests(runner, ShellState())
            self.assertIn("file-backed posthoc note", output.getvalue())

    def test_foreground_command_records_job_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1")
            self.assertEqual([event.topic for event in events], ["host.found"])
            topics = runner.db.topics()
            self.assertIn("job.requested", topics)
            self.assertIn("job.claimed", topics)
            self.assertIn("job.started", topics)
            self.assertIn("job.finished", topics)
            self.assertEqual(runner.db.job()[0]["status"], "finished")

    def test_hostscanner_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="hostscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
            contextlib.redirect_stdout(output),
        ):
            events = list(HostScanner().run(context, ["-s", "127.0.0.1"], []))
        self.assertEqual(events[0]["host"], "127.0.0.1")
        self.assertEqual(output.getvalue(), "")

    def test_hostscanner_expands_range_before_nmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                return_value=["192.168.0.1"],
            ) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-2")
            discover.assert_called_once_with("192.168.0.1 192.168.0.2", "-sn")

    def test_hostscanner_resolves_name_before_nmap(self):
        address_info = [
            (2, 1, 6, "", ("203.0.113.10", 0)),
            (2, 1, 6, "", ("203.0.113.11", 0)),
            (2, 1, 6, "", ("203.0.113.10", 0)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch(
                    "bywaf.plugins.discovery.hostscanner.socket.getaddrinfo",
                    return_value=address_info,
                ) as getaddrinfo,
                patch(
                    "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                    return_value=["203.0.113.10"],
                ) as discover,
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner example.test")
            getaddrinfo.assert_called_once_with("example.test", None, type=socket.SOCK_STREAM)
            discover.assert_called_once_with("203.0.113.10 203.0.113.11", "-sn")
            host_events = [event for event in events if event.topic == "host.found"]
            self.assertEqual(host_events[0].payload["host"], "203.0.113.10")
            self.assertEqual(host_events[0].payload["name"], "example.test")
            resolved = runner.db.events_for_topic("name.resolved")
            self.assertEqual(resolved[0].payload["name"], "example.test")
            self.assertEqual(resolved[0].payload["addresses"], ["203.0.113.10", "203.0.113.11"])

    def test_hostscanner_rejects_unresolved_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "bywaf.plugins.discovery.hostscanner.socket.getaddrinfo",
                side_effect=socket.gaierror,
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with self.assertRaisesRegex(ValueError, "could not resolve host: missing.test"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        runner.execute("hostscanner missing.test")

    def test_hostscanner_except_removes_targets_before_nmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-3 except=192.168.0.2,192.168.0.3")
            discover.assert_called_once_with("192.168.0.1", "-sn")

    def test_hostscanner_except_supports_at_file_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            excluded = Path(tmp, "excluded.txt")
            excluded.write_text("192.168.0.2\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner 192.168.0.1-2 except=@lines:{excluded}")
            discover.assert_called_once_with("192.168.0.1", "-sn")

    def test_hostscanner_plan_shows_intended_targets_without_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts") as discover,
                contextlib.redirect_stdout(output),
            ):
                events = runner.execute("hostscanner 192.168.0.1-2 --test")
                process_framework_requests(runner, ShellState())
            self.assertEqual(events, [])
            discover.assert_not_called()
            self.assertIn("Plan: scan-hosts", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("plan.requested")[0].payload["summary"], "Scan 2 host target(s) with nmap arguments '-sn'.")
            self.assertEqual(runner.db.events_for_topic("policy.evaluated")[0].payload["decision"], "allow")

    def test_hostscanner_plan_yes_applies_prune_repair_and_audits_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.policy.network.allow", "192.168.0.0/24")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1 10.0.0.1 --yes")
            discover.assert_called_once_with("192.168.0.1", "-sn")
            self.assertEqual(runner.db.events_for_topic("plan.approved")[0].payload["approval_method"], "cli-yes")
            repair = runner.db.events_for_topic("plan.repair.applied")[0]
            self.assertEqual(repair.payload["repair"], "prune-out-of-scope")
            self.assertTrue(repair.payload["approved_by"])

    def test_expand_targets_enforces_limit(self):
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            expand_targets(["192.168.0.1-3"], 2)

    def test_pipeline_scans_open_local_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[
                        NmapPort(
                            host="127.0.0.1",
                            port=8080,
                            protocol="tcp",
                            state="open",
                            service="http",
                        )
                    ],
                ),
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    events = runner.execute("hostscanner 127.0.0.1 | portscanner port=8080")
                    process_framework_requests(runner, ShellState())
                self.assertEqual(events[-1].topic, "port.open")
                self.assertEqual(events[-1].payload["port"], 8080)
                self.assertEqual(events[-1].payload["scanner"], "nmap")
                self.assertIsNotNone(events[0].pipeline_id)
                self.assertEqual(events[-1].parent_command_run_id, events[0].command_run_id)
                self.assertIn("portscanner <", output.getvalue())
                self.assertIn(">: discovered port 8080/tcp on host 127.0.0.1", output.getvalue())
                alerts = runner.db.events_for_topic("console.alert")
                self.assertTrue(any("discovered port 8080/tcp" in event.payload["message"] for event in alerts))
                completed = runner.db.events_for_topic("plugin.progress.completed")
                self.assertEqual(completed[-1].payload["phase"], "port_scan")
                self.assertEqual(completed[-1].payload["open_ports"], 1)
                self.assertEqual(len(runner.db.events_for_topic("port.open")), 1)

    def test_portscanner_does_not_emit_events_for_closed_scanned_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.plugins.network.portscanner.scan_open_ports", return_value=[]):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner port=1-1000 127.0.0.1")
            self.assertEqual(events, [])
            self.assertEqual(runner.db.events_for_topic("port.open"), [])
            topics = {event.topic for event in runner.db.recent_events(100)}
            self.assertNotIn("port.closed", topics)
            self.assertNotIn("port.filtered", topics)
            completed = runner.db.events_for_topic("plugin.progress.completed")
            self.assertEqual(completed[-1].payload["phase"], "port_scan")
            self.assertEqual(completed[-1].payload["open_ports"], 0)

    def test_portscanner_promotes_telnet_open_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[
                    NmapPort(
                        host="192.0.2.10",
                        port=23,
                        protocol="tcp",
                        state="open",
                        service="telnet",
                    )
                ],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner port=23 192.0.2.10")

            candidates = runner.db.events_for_topic("finding.candidate")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].payload["title"], "Telnet service exposed")
            self.assertEqual(candidates[0].payload["target"]["port"], "23")
            self.assertEqual(candidates[0].payload["confidence"], "high")

    def test_portscanner_promotes_telnet_on_nonstandard_port_from_service_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[
                    NmapPort(
                        host="192.0.2.10",
                        port=2323,
                        protocol="tcp",
                        state="open",
                        service="telnet",
                    )
                ],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner port=2323 192.0.2.10")

            candidates = runner.db.events_for_topic("finding.candidate")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].payload["target"]["port"], "2323")
            self.assertEqual(candidates[0].payload["confidence"], "high")

    def test_portscanner_default_telnet_port_without_service_detection_is_medium_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[
                    NmapPort(
                        host="192.0.2.10",
                        port=23,
                        protocol="tcp",
                        state="open",
                        service="",
                    )
                ],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner port=23 192.0.2.10")

            candidates = runner.db.events_for_topic("finding.candidate")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].payload["confidence"], "medium")
            self.assertIn("confirm service identity", candidates[0].payload["evidence"])

    def test_commandlet_can_use_events_from_prior_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="host-run",
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner --from step=host-run port=80")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            self.assertEqual(scan.call_args.args[0], ["127.0.0.1"])

    def test_commandlet_can_use_events_from_prior_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", 123, "finished")
            runner.db.publish(
                "host.found",
                {"host": "127.0.0.1", "job_id": job_id},
                "hostscanner",
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute(f"portscanner --from job={job_id} topic=host.found port=80")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            self.assertEqual(scan.call_args.args[0], ["127.0.0.1"])

    def test_portscanner_port_variable_is_default_but_cli_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("network/portscanner.port", "22")
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 22, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner 127.0.0.1")
            self.assertEqual(scan.call_args.args[1], "22")
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner port=80 127.0.0.1")
            self.assertEqual(scan.call_args.args[1], "80")

    def test_portscanner_accepts_key_value_host_list_and_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("192.0.2.10", 33169, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner host=192.0.2.10 port=33169,33199")
            self.assertEqual(scan.call_args.args[0], ["192.0.2.10"])
            self.assertEqual(scan.call_args.args[1], "33169,33199")
            self.assertEqual(events[0].payload["port"], 33169)

    def test_portscanner_keeps_cidr_and_ip_range_targets_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.network.portscanner.resolve_target", side_effect=AssertionError("should not resolve IP ranges")),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.10", 80, "tcp", "open")],
                ) as scan,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner host=192.0.2.0/24 192.0.3.1-5 port=80")
            self.assertCountEqual(scan.call_args.args[0], ["192.0.2.0/24", "192.0.3.1-5"])

    def test_portscanner_accepts_singular_host_and_records_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.network.portscanner.resolve_target", return_value=("192.0.2.55",)),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.55", 33169, "tcp", "open")],
                ) as scan,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner host=example.test port=33169")
            self.assertEqual(scan.call_args.args[0], ["192.0.2.55"])
            self.assertEqual(events[0].payload["host"], "192.0.2.55")
            resolved = runner.db.events_for_topic("name.resolved")
            self.assertEqual(resolved[0].payload["name"], "example.test")
            self.assertEqual(resolved[0].payload["addresses"], ["192.0.2.55"])

    def test_portscanner_filters_resolved_addresses_for_ipv4_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.network.portscanner.resolve_target", return_value=("192.0.2.55", "2001:db8::55")),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.55", 443, "tcp", "open")],
                ) as scan,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute('portscanner host=example.test port=443 arguments="-Pn -sT -4"')
            self.assertEqual(scan.call_args.args[0], ["192.0.2.55"])
            self.assertEqual(events[0].payload["host"], "192.0.2.55")
            resolved = runner.db.events_for_topic("name.resolved")
            self.assertEqual(resolved[0].payload["addresses"], ["192.0.2.55"])

    def test_portscanner_filters_resolved_addresses_for_ipv6_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.network.portscanner.resolve_target", return_value=("192.0.2.55", "2001:db8::55")),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("2001:db8::55", 443, "tcp", "open")],
                ) as scan,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute('portscanner host=example.test port=443 arguments="-Pn -sT -6"')
            self.assertEqual(scan.call_args.args[0], ["2001:db8::55"])
            self.assertEqual(events[0].payload["host"], "2001:db8::55")
            resolved = runner.db.events_for_topic("name.resolved")
            self.assertEqual(resolved[0].payload["addresses"], ["2001:db8::55"])

    def test_portscanner_except_skips_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner 127.0.0.1 127.0.0.2 except=127.0.0.2")
            self.assertEqual(scan.call_args.args[0], ["127.0.0.1"])

    def test_portscanner_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="portscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ),
            contextlib.redirect_stdout(output),
        ):
            events = list(PortScanner().run(context, ["-s", "127.0.0.1"], []))
        self.assertEqual(events[0]["port"], 80)
        self.assertEqual(output.getvalue(), "")

    def test_portscanner_quiet_alias_suppresses_alert(self):
        context = CommandContext(db=None, source="portscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("127.0.0.1", 80, "tcp", "open")],
            ),
            contextlib.redirect_stdout(output),
        ):
            events = list(PortScanner().run(context, ["--quiet", "127.0.0.1"], []))
        self.assertEqual(events[0]["port"], 80)
        self.assertEqual(output.getvalue(), "")

    def test_portscanner_listen_scopes_to_upstream_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "192.0.2.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            db.publish(
                "host.found",
                {"host": "198.51.100.1"},
                "hostscanner",
                pipeline_id="pipe-2",
                command_run_id="upstream-1",
            )
            context = CommandContext(
                db,
                source="portscanner",
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                },
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[
                    NmapPort(
                        host="192.0.2.1",
                        port=443,
                        protocol="tcp",
                        state="open",
                    )
                ],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))
            self.assertEqual(events[0]["host"], "192.0.2.1")
            scan.assert_called_once()
            self.assertEqual(scan.call_args.args[0], ["192.0.2.1"])

    def test_portscanner_listen_requires_upstream_pipeline_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(EventStore(Path(tmp, "db.sqlite3")), source="portscanner")
            with self.assertRaisesRegex(ValueError, "pipeline scope"):
                list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))

    def test_background_portscanner_auto_listens_to_upstream_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "203.0.113.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            context = CommandContext(
                db,
                source="portscanner",
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                    "background": True,
                },
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("203.0.113.1", 80, "tcp", "open")],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen-timeout", "0.01"], []))
            self.assertEqual(events[0]["host"], "203.0.113.1")

    def test_pipeline_portscanner_auto_listens_to_upstream_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "203.0.113.5"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            context = CommandContext(
                db,
                source="portscanner",
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                    "background": False,
                },
            )
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("203.0.113.5", 443, "tcp", "open")],
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen-timeout", "0.01"], []))
            self.assertEqual(events[0]["host"], "203.0.113.5")

    def test_pipeline_attach_starts_scoped_background_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="host-run-1",
            )
            latest_id = runner.db.latest_event_id()
            with patch("bywaf.runner.core.mp.Process") as process_cls:
                process_cls.return_value.pid = 123
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("pipeline attach pipe-1 portscanner step=host-run-1 since=now --listen-timeout 1")
            process_cls.return_value.start.assert_called_once()
            process_args = process_cls.call_args.kwargs["args"]
            self.assertEqual(process_args[4], "pipe-1")
            stage = process_args[5]
            self.assertEqual(stage.parent_command_run_id, "host-run-1")
            self.assertEqual(stage.invocation.name, "portscanner")
            self.assertEqual(stage.invocation.args, ["--listen-timeout", "1"])
            self.assertEqual(stage.invocation.from_pipeline, "pipe-1")
            self.assertEqual(stage.invocation.from_step, "host-run-1")
            self.assertGreaterEqual(stage.invocation.replay_after_id, latest_id)
            attached = runner.db.events_for_topic("pipeline.attached")[0]
            self.assertEqual(attached.payload["since"], "now")
            self.assertEqual(attached.payload["pipeline_id"], "pipe-1")
            self.assertEqual(attached.payload["parent_command_run_id"], "host-run-1")

    def test_background_command_records_job_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            with patch("bywaf.plugins.network.nmap_backend.load_backend", return_value=("fake", FakeNmapModule())):
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 &")
            self.assertEqual(events[0].topic, "job.requested")
            db = EventStore(db_path)
            deadline = time.time() + 5
            found = []
            while time.time() < deadline:
                found = db.fetch(Subscription(("host.found",)))
                if found:
                    break
                time.sleep(0.1)
            self.assertEqual(found[0].payload["host"], "127.0.0.1")
            topics = db.topics()
            while "job.finished" not in topics and time.time() < deadline:
                time.sleep(0.1)
                topics = db.topics()
            self.assertIn("job.claimed", topics)
            self.assertIn("job.started", topics)
            self.assertIn("job.finished", topics)

    def test_background_job_preserves_attached_stage_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.runner.core.mp.Process") as process_cls:
                process = process_cls.return_value
                process.pid = 123
                runner.execute("hostscanner 127.0.0.1& | portscanner&")
            self.assertEqual(
                process_cls.call_args.kwargs["args"][3],
                "hostscanner 127.0.0.1& | portscanner&",
            )
            self.assertIsNone(process_cls.call_args.kwargs["args"][1])

    def test_background_job_exits_quietly_when_database_is_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_path = Path(tmp, "deleted", "db.sqlite3")
        run_background_job(str(missing_path), None, 1, "job", "pipeline-test", ())

    def test_background_job_records_failure_without_reraising(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("missing", None, "queued")
            run_background_job(str(db.path), None, job_id, "missing", "pipeline-test", ())
            job = db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            failure = db.events_for_topic("job.failed")[0]
            self.assertEqual(failure.payload["job_id"], job_id)
            self.assertEqual(failure.payload["command"], "missing")
            self.assertIn("started_at", failure.payload)

    def test_watchdog_emits_timeout_and_stall_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            with db.connect() as conn:
                conn.execute("UPDATE jobs SET started_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", job_id))
            context = CommandContext(db, "watchdog", VarStore())
            list(Watchdog().run(context, ["--once", "-s", "timeout=1", "stall-threshold=1", "error-threshold=99"], ()))
            self.assertEqual(db.events_for_topic("watchdog.timeout")[0].payload["job_id"], job_id)
            self.assertEqual(db.events_for_topic("watchdog.stalled")[0].payload["job_id"], job_id)

    def test_watchdog_emits_error_rate_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", 123, "running")
            db.publish("tool.error", {"job_id": job_id, "message": "first"}, "test")
            db.publish("tool.error", {"job_id": job_id, "message": "second"}, "test")
            context = CommandContext(db, "watchdog", VarStore())
            list(Watchdog().run(context, ["--once", "-s", "timeout=999999", "stall-threshold=999999", "error-threshold=2"], ()))
            event = db.events_for_topic("watchdog.error_rate")[0]
            self.assertEqual(event.payload["job_id"], job_id)
            self.assertEqual(event.payload["observed"], 2)



class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
