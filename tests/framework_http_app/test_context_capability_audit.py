"""Framework HTTP app tests for test context capability audit."""

from pathlib import Path
import tempfile
import unittest

from bywaf.app import make_runner
from bywaf.plugin import CommandContext
from bywaf.varstore import VarStore


class TestContextCapabilityAuditTests(unittest.TestCase):
    def test_context_records_declared_capability_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("framework.console.output",)},
            )
            context.output("hello")
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "framework.console.output")
            self.assertTrue(used.payload["declared"])
            self.assertEqual(runner.db.events_for_topic("plugin.capability.missing"), [])

    def test_context_records_missing_capability_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin")
            context.output("hello")
            missing = runner.db.events_for_topic("plugin.capability.missing")[0]
            self.assertEqual(missing.payload["capability"], "framework.console.output")
            self.assertFalse(missing.payload["declared"])

    def test_context_events_publish_uses_scope_and_audits_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={
                    "pipeline_id": "pipeline-1",
                    "command_run_id": "run-1",
                    "capabilities": ("db.write:test.topic",),
                },
            )
            event = context.events.publish("test.topic", {"ok": True})
            self.assertEqual(event.pipeline_id, "pipeline-1")
            self.assertEqual(event.command_run_id, "run-1")
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.write:test.topic")
            self.assertTrue(used.payload["declared"])

    def test_context_events_publish_validates_schema_backed_topic_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin")

            with self.assertRaisesRegex(ValueError, "invalid port.open event"):
                context.events.publish("port.open", {"host": "127.0.0.1", "port": "80", "protocol": "tcp"})

            self.assertEqual(runner.db.events_for_topic("port.open"), [])

    def test_context_events_publish_schema_validation_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            store = VarStore()
            store.set("global.schema.validation", "off")
            context = CommandContext(runner.db, source="plugin", _varstore=store)

            event = context.events.publish("port.open", {"host": "127.0.0.1", "port": "80", "protocol": "tcp"})

            self.assertEqual(event.topic, "port.open")
            self.assertEqual(runner.db.events_for_topic("port.open")[0].payload["port"], "80")

    def test_context_events_fetch_audits_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("test.topic", {"ok": True}, "test")
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.read:test.topic",)},
            )
            events = context.events.fetch(("test.topic",))
            self.assertEqual(events[0].payload["ok"], True)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.read:test.topic")
            self.assertTrue(used.payload["declared"])

    def test_context_events_does_not_audit_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.write:test.topic",)},
            )
            context.events.publish("test.topic", {"ok": True})
            capabilities = [
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            ]
            self.assertEqual(capabilities, ["db.write:test.topic"])

    def test_narrow_store_accessors_do_not_audit_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(runner.db, source="plugin")
            self.assertIs(context.event_store(), runner.db)
            self.assertIs(context.runtime_store(), runner.db)
            self.assertEqual(runner.db.events_for_topic("plugin.capability.used"), [])

    def test_artifact_store_accessor_audits_artifact_access_not_raw_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("artifact.read", "artifact.write")},
            )
            self.assertIsNotNone(context.artifact_store(read_access=True, write_access=True))
            capabilities = [
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            ]
            self.assertEqual(capabilities, ["artifact.read", "artifact.write"])

    def test_maintenance_store_accessor_audits_raw_db_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.raw",)},
            )
            self.assertIs(context.maintenance_store(), runner.db)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.raw")
            self.assertTrue(used.payload["declared"])

    def test_raw_context_db_access_audits_db_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capabilities": ("db.raw",)},
            )
            self.assertIsNotNone(context.db)
            used = runner.db.events_for_topic("plugin.capability.used")[0]
            self.assertEqual(used.payload["capability"], "db.raw")
            self.assertTrue(used.payload["declared"])

    def test_raw_context_db_access_is_denied_in_enforce_mode_without_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                runner.db,
                source="plugin",
                metadata={"capability_mode": "enforce"},
            )

            with self.assertRaisesRegex(PermissionError, "db.raw"):
                _ = context.db

            missing = runner.db.events_for_topic("plugin.capability.missing")[0]
            self.assertEqual(missing.payload["capability"], "db.raw")


if __name__ == "__main__":
    unittest.main()
