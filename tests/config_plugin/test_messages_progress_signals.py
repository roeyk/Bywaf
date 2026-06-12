# ruff: noqa: F403,F405
"""Config/plugin tests split by responsibility."""

from tests.config_plugin.support import *  # noqa: F403,F405
class ConfigPluginMessagesProgressSignalTests(unittest.TestCase):
    """Groups regression coverage for config/plugin tests split by responsibility."""
    def test_host_message_json_round_trip(self):
        host = Host(run_id="1", host="127.0.0.1")
        self.assertEqual(Host.from_json(host.to_json()), host)

    def test_progress_percent(self):
        self.assertEqual(Progress(run_id="1", status="x", total=4, completed=1).percent, 25)

    def test_context_progress_emits_structured_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            context = CommandContext(
                db,
                source="scanner",
                metadata={"job_id": 7, "pipeline_id": "pipe-1", "command_run_id": "run-1"},
            )
            context.progress_started(phase="scan", current=0, total=10, unit="hosts")
            context.progress(phase="scan", current=1, total=10, unit="hosts", message="scanning")
            context.progress_completed(phase="scan", current=10, total=10, unit="hosts")
            events = db.events_matching(pipeline_id="pipe-1")
            topics = [event.topic for event in events if event.topic.startswith("plugin.progress.")]
            self.assertEqual(
                topics,
                ["plugin.progress.started", "plugin.progress.updated", "plugin.progress.completed"],
            )
            updated = [event for event in events if event.topic == "plugin.progress.updated"][0]
            self.assertEqual(updated.payload["percent"], 10.0)
            self.assertEqual(updated.payload["job_id"], 7)

    def test_context_progress_throttle_is_framework_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            store = VarStore()
            store.set("global.progress.min-interval-ms", "100000")
            store.set("global.progress.min-percent-delta", "10")
            context = CommandContext(
                db,
                source="scanner",
                _varstore=store,
                metadata={"pipeline_id": "pipe-1", "command_run_id": "run-1"},
            )
            self.assertIsNotNone(context.progress(phase="scan", current=1, total=100))
            self.assertIsNone(context.progress(phase="scan", current=2, total=100))
            self.assertIsNotNone(context.progress(phase="scan", current=11, total=100))
            self.assertIsNotNone(context.progress(phase="other", current=12, total=100))
            self.assertIsNotNone(context.progress_completed(phase="other", current=100, total=100))
            progress_events = [
                event
                for event in db.events_matching(pipeline_id="pipe-1")
                if event.topic.startswith("plugin.progress.")
            ]
            self.assertEqual(len(progress_events), 4)

    def test_context_signals_filters_and_responds(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            request = db.publish(
                "runtime.signal.requested",
                {"target_type": "run", "target_id": "run-1", "action": "prune", "args": {"targets": "192.168.1.0/24"}},
                "framework",
                command_run_id="run-1",
            )
            db.publish(
                "runtime.signal.requested",
                {"target_type": "run", "target_id": "other-run", "action": "mute", "args": {}},
                "framework",
                command_run_id="other-run",
            )
            context = CommandContext(db, source="hostscanner", metadata={"pipeline_id": "pipe-1", "command_run_id": "run-1"})
            pending = context.signals.pending(action="prune")
            self.assertEqual([event.id for event in pending], [request.id])
            context.signals.applied(pending[0], "pruned pending targets", count=3)
            applied = db.events_for_topic("runtime.signal.applied")[0]
            self.assertEqual(applied.payload["request_event_id"], request.id)
            self.assertEqual(applied.payload["details"]["count"], 3)
