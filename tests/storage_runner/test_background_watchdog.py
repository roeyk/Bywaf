# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility."""

from datetime import datetime

from tests.storage_runner.support import *  # noqa: F403,F405


class ImmediateProcess:
    """Test double used by this module's regression cases."""
    pid = 123

    def __init__(self, *, target, args, daemon):
        self.target = target
        self.args = args
        self.daemon = daemon

    def start(self):
        self.target(*self.args)


class StorageRunnerBackgroundWatchdogTests(unittest.TestCase):
    """Groups regression coverage for storage runner tests split by responsibility."""
    def test_background_command_records_job_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            with (
                patch("bywaf.runner.core.mp.Process", ImmediateProcess),
                patch("bywaf.plugins.network.nmap_backend.load_backend", return_value=("fake", FakeNmapModule())),
            ):
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

    def test_runner_rejects_unknown_command_without_recording_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with self.assertRaisesRegex(KeyError, "unknown commandlet: missing"):
                runner.execute("missing")
            self.assertEqual(runner.db.jobs(), [])

    def test_job_timestamps_use_operator_local_timezone(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job("hostscanner 127.0.0.1", None, "queued")
            job = db.job(job_id)
            self.assertIsNotNone(job)
            assert job is not None
            started_at = datetime.fromisoformat(str(job["started_at"]))
            self.assertEqual(started_at.utcoffset(), datetime.now().astimezone().utcoffset())

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
