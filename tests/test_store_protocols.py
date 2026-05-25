"""Tests for store protocols behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import tempfile
import unittest

from bywaf.artifacts import ArtifactStore
from bywaf.db import EventStore, SQLiteBackend, Subscription
from bywaf.stores import (
    ArtifactStoreProtocol,
    EventStoreProtocol,
    MaintenanceStoreProtocol,
    RuntimeStoreProtocol,
    VariableStoreProtocol,
)
from bywaf.varstore import VarStore


class StoreProtocolTests(unittest.TestCase):
    def test_event_store_satisfies_event_runtime_and_maintenance_protocols(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp, "events.sqlite3"))
            self.assertIsInstance(store, EventStoreProtocol)
            self.assertIsInstance(store, RuntimeStoreProtocol)
            self.assertIsInstance(store, MaintenanceStoreProtocol)

            published = store.publish("test.topic", {"value": 1}, "test")
            self.assertEqual(store.fetch(Subscription(("test.topic",))), [published])
            self.assertEqual(store.events_matching(topic="test.topic"), [published])
            self.assertEqual(store.latest_event_id(), published.id)

            job_id = store.record_job("test", None, "queued")
            self.assertTrue(store.claim_job(job_id, 123))
            store.finish_job(job_id, "completed")
            job = store.job(job_id)
            assert job is not None
            self.assertEqual(job["status"], "completed")

    def test_event_store_can_use_explicit_database_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = SQLiteBackend(Path(tmp, "events.sqlite3"))
            store = EventStore(backend=backend)

            published = store.publish("test.topic", {"value": 1}, "test")

            self.assertIs(store.backend, backend)
            self.assertEqual(store.path, backend.path)
            self.assertEqual(store.event_by_id(published.id or 0), published)

    def test_event_store_backend_opens_fresh_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp, "events.sqlite3"))

            with store.connect() as first:
                with store.connect() as second:
                    self.assertIsNot(first, second)

    def test_artifact_store_satisfies_artifact_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp, "example.txt")
            artifact_path.write_text("artifact body", encoding="utf-8")
            store = ArtifactStore(Path(tmp, "artifacts.sqlite3"))
            self.assertIsInstance(store, ArtifactStoreProtocol)

            artifact = store.attach_file(artifact_path, commandlet="test")
            self.assertEqual(store.get(artifact.id).body, b"artifact body")
            self.assertEqual(store.list(command_run_id="missing"), [])
            self.assertTrue(store.verify([artifact])[0].ok)

    def test_varstore_satisfies_variable_store_protocol(self):
        store = VarStore()
        self.assertIsInstance(store, VariableStoreProtocol)
        store.set("global.example", "value")
        store.update_prefixed("plugin", {"timeout": 3})
        self.assertEqual(store.get("global.example"), "value")
        self.assertEqual(store.get("plugin.timeout"), "3")
        self.assertEqual(store.names(), ["global.example", "plugin.timeout"])


if __name__ == "__main__":
    unittest.main()
