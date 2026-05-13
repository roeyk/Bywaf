from pathlib import Path
import tempfile
import unittest

from bywaf.db import EventStore, Subscription, database_appears_encrypted, sqlcipher_available
from bywaf.events import Event


class EventDbTests(unittest.TestCase):
    def test_event_serializes_payload(self):
        event = Event.new("topic", {"b": 2, "a": 1}, "test")
        self.assertEqual(event.payload_json(), '{"a":1,"b":2}')

    def test_publish_and_fetch_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            published = db.publish(
                "host.found",
                {"host": "127.0.0.1"},
                "test",
                pipeline_id="pipe-1",
                command_run_id="cmd-1",
            )
            fetched = db.fetch(Subscription(("host.found",)))
            self.assertEqual(fetched, [published])
            self.assertEqual(fetched[0].pipeline_id, "pipe-1")
            self.assertEqual(fetched[0].command_run_id, "cmd-1")

    def test_fetch_can_scope_by_pipeline_and_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("host.found", {"host": "a"}, "test", pipeline_id="pipe-1", command_run_id="cmd-1")
            db.publish("host.found", {"host": "b"}, "test", pipeline_id="pipe-2", command_run_id="cmd-1")
            db.publish("host.found", {"host": "c"}, "test", pipeline_id="pipe-1", command_run_id="cmd-2")
            fetched = db.fetch(
                Subscription(("host.found",), pipeline_id="pipe-1", command_run_id="cmd-1")
            )
            self.assertEqual([event.payload["host"] for event in fetched], ["a"])

    def test_fetch_respects_after_id_and_topic(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            first = db.publish("a", {"n": 1}, "test")
            db.publish("b", {"n": 2}, "test")
            self.assertEqual(db.fetch(Subscription(("a",), after_id=first.id or 0)), [])

    def test_poll_returns_without_timeout_when_event_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("a", {"n": 1}, "test")
            self.assertEqual(len(db.poll(Subscription(("a",)), timeout_seconds=0.1)), 1)

    def test_jobs_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            job_id = db.record_job("list", 123, "running")
            db.finish_job(job_id, "finished")
            rows = db.jobs()
            self.assertEqual(rows[0]["status"], "finished")

    def test_checkpoint_runs_without_losing_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("topic", {"value": 1}, "test")
            db.checkpoint()
            self.assertEqual(db.events_for_topic("topic")[0].payload["value"], 1)

    def test_events_matching_filters_run_pipeline_and_topic(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("a", {"n": 1}, "one", pipeline_id="pipe-1", command_run_id="run-1")
            db.publish("a", {"n": 2}, "one", pipeline_id="pipe-2", command_run_id="run-1")
            db.publish("b", {"n": 3}, "two", pipeline_id="pipe-1", command_run_id="run-2")
            events = db.events_matching(topic="a", pipeline_id="pipe-1", command_run_id="run-1")
            self.assertEqual([event.payload["n"] for event in events], [1])

    def test_sql_like_filter_values_are_bound_as_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            topic = "x' OR 1=1 --"
            db.publish(topic, {"n": 1}, "one", pipeline_id="pipe", command_run_id="run")
            db.publish("safe", {"n": 2}, "one", pipeline_id="pipe", command_run_id="run")
            events = db.events_matching(topic=topic)
            self.assertEqual([event.payload["n"] for event in events], [1])

    def test_runs_summarizes_command_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="p", command_run_id="r")
            db.publish("host.found", {"host": "127.0.0.2"}, "hostscanner", pipeline_id="p", command_run_id="r")
            rows = db.runs()
            self.assertEqual(rows[0]["command_run_id"], "r")
            self.assertEqual(rows[0]["events"], 2)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_encrypted_database_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "encrypted.sqlite3")
            db = EventStore(path, passphrase="secret")
            db.publish("topic", {"value": 1}, "test")
            self.assertTrue(database_appears_encrypted(path))
            reopened = EventStore(path, passphrase="secret")
            self.assertEqual(reopened.events_for_topic("topic")[0].payload["value"], 1)


if __name__ == "__main__":
    unittest.main()
