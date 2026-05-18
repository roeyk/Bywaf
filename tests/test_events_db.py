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
            db.update_job_pid(job_id, 456)
            job = db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["pid"], 456)
            self.assertTrue(str(job["serial"]).startswith("job-"))
            self.assertEqual(db.job_serial(job_id), job["serial"])
            db.finish_job(job_id, "finished")
            rows = db.jobs()
            self.assertEqual(rows[0]["status"], "finished")

    def test_runtime_local_ids_are_persisted_and_not_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.publish("host.found", {"host": "a"}, "hostscanner", pipeline_id="pipe-a", command_run_id="run-a")
            db.publish("host.found", {"host": "b"}, "hostscanner", pipeline_id="pipe-b", command_run_id="run-b")
            self.assertEqual(db.run_aliases(), {"run-a": "1", "run-b": "2"})
            self.assertEqual(db.pipeline_aliases(), {"pipe-a": "1", "pipe-b": "2"})
            with db.connect() as conn:
                conn.execute("DELETE FROM events WHERE command_run_id = ?", ("run-a",))
            db.publish("host.found", {"host": "c"}, "hostscanner", pipeline_id="pipe-c", command_run_id="run-c")
            self.assertEqual(db.run_aliases()["run-b"], "2")
            self.assertEqual(db.run_aliases()["run-c"], "3")
            self.assertEqual(db.resolve_run_serial("2"), "run-b")
            self.assertEqual(db.resolve_pipeline_serial("2"), "pipe-b")

    def test_job_serials_are_searchable_serials(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            job_id = db.record_job("job list", 123, "running")
            serial = db.job_serial(job_id)
            self.assertIsNotNone(serial)
            assert serial is not None
            db.publish("job.requested", {"job_id": job_id, "job_serial": serial, "serial": serial}, "runner")
            self.assertIn(serial, db.serials())
            self.assertEqual(db.events_for_serial(serial)[0].payload["job_id"], job_id)

    def test_cancellation_records_match_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            db.request_cancellation("job", "7")
            self.assertTrue(db.cancellation_requested(job_id=7))
            self.assertFalse(db.cancellation_requested(job_id=8))

    def test_claim_job_is_atomic_for_queued_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", None, "queued")
            self.assertTrue(db.claim_job(job_id, 123))
            self.assertFalse(db.claim_job(job_id, 456))
            job = db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "claimed")
            self.assertEqual(job["pid"], 123)

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

    def test_pipelines_can_filter_to_active_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "events.sqlite3"))
            active_job = db.record_job("hostscanner active", 123, "running")
            finished_job = db.record_job("hostscanner done", 456, "finished")
            db.record_command_run_vars(
                job_id=active_job,
                pipeline_id="active-pipe",
                command_run_id="active-run",
                commandlet="hostscanner",
                values={"marker": "active"},
            )
            db.record_command_run_vars(
                job_id=finished_job,
                pipeline_id="finished-pipe",
                command_run_id="finished-run",
                commandlet="hostscanner",
                values={"marker": "finished"},
            )
            self.assertEqual([row["pipeline_id"] for row in db.pipelines(active_only=True)], ["active-pipe"])
            self.assertEqual(
                {row["pipeline_id"] for row in db.pipelines(active_only=False)},
                {"active-pipe", "finished-pipe"},
            )

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
