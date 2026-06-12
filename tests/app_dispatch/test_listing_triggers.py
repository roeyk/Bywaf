"""Tests for app listing triggers behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: app dispatch listing triggers regression behavior.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    dispatch_repl_line,
    make_runner,
    shutdown_runner,
)
from bywaf.event import Event
from bywaf.specs import TriggerSpec
from bywaf.triggers import start_default_services



class AppDispatchTests(unittest.TestCase):
    """Groups regression coverage for app listing triggers behavior."""
    def test_dispatch_plugins_lists_plugins(self):
        """Protect dispatch plugins lists plugins behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "plugins")
            text = output.getvalue()
            self.assertIn("PLUGIN", text)
            self.assertIn("CMDS", text)
            self.assertIn("WHAT IT DOES", text)
            self.assertIn("discovery", text)
            self.assertIn("Host and target discovery commandlets.", text)

    def test_dispatch_cmds_lists_commandlets_grouped_by_plugin(self):
        """Protect dispatch cmds lists commandlets grouped by plugin behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "cmds")
            text = output.getvalue()
            self.assertIn("PLUGIN", text)
            self.assertIn("COMMANDLET", text)
            self.assertIn("WHAT IT DOES", text)
            self.assertIn("os", text)
            self.assertIn("ls", text)
            self.assertIn("List files in a local directory.", text)

    def test_dispatch_triggers_lists_provider_rules(self):
        """Protect dispatch triggers lists provider rules behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                dispatch_repl_line(runner, "triggers")
            text = output.getvalue()
            self.assertIn("network-access-start", text)
            self.assertIn("plugin.capability", text)

    def test_dispatch_cmds_page_uses_system_pager_for_generated_output(self):
        """Protect dispatch cmds page uses system pager for generated output behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((40, 4))),
                patch("bywaf.pager.subprocess.run") as run,
            ):
                dispatch_repl_line(runner, "cmds --page")
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/less")
            self.assertEqual(argv[1], "-R")
            self.assertEqual(argv[2], "--")
            self.assertFalse(Path(argv[3]).exists())
            self.assertEqual(run.call_args.kwargs["env"]["LESSSECURE"], "1")

    def test_dispatch_cmds_page_ignores_pager_keyboard_interrupt(self):
        """Protect dispatch cmds page ignores pager keyboard interrupt behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.pager.shutil.which", return_value="/usr/bin/less"),
                patch("bywaf.pager.sys.stdin.isatty", return_value=True),
                patch("bywaf.pager.sys.stdout.isatty", return_value=True),
                patch("bywaf.pager.shutil.get_terminal_size", return_value=os.terminal_size((40, 4))),
                patch("bywaf.pager.subprocess.run", side_effect=KeyboardInterrupt),
            ):
                dispatch_repl_line(runner, "cmds --page")

    def test_start_default_services_launches_session_watchdog_once(self):
        """Protect start default services launches session watchdog once behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", None, "running")
            trigger_event = runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": job_id,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
                start_default_services(runner)
            start.assert_called_once_with("watchdog --session-service")
            self.assertEqual(runner.session_service_job_ids, {7})
            state = runner.db.trigger_states()[0]
            self.assertEqual(state["name"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(state["enabled"], 1)
            self.assertEqual(state["last_fired_event_id"], trigger_event.id)
            enabled = runner.db.events_for_topic("framework.trigger.enabled")[0]
            self.assertEqual(enabled.payload["trigger_id"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(enabled.payload["provider"], "runtime.watchdog")
            self.assertEqual(enabled.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(enabled.payload["action_command"], "watchdog --session-service")
            fired = runner.db.events_for_topic("framework.trigger.fired")[0]
            self.assertEqual(fired.payload["trigger_id"], "runtime.watchdog.network-access-starts-watchdog")
            self.assertEqual(fired.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(fired.payload["trigger_event_id"], trigger_event.id)
            self.assertEqual(fired.payload["trigger_event_topic"], "plugin.capability.used")

    def test_start_default_services_waits_for_network_capability_event(self):
        """Protect start default services waits for network capability event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()
            self.assertEqual(runner.session_service_job_ids, set())
            self.assertEqual(len(runner.db.events_for_topic("framework.trigger.enabled")), 1)

    def test_start_default_services_does_not_rewrite_idle_trigger_state(self):
        """Protect start default services does not rewrite idle trigger state behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            start_default_services(runner)

            with patch.object(runner.db, "update_trigger_state", wraps=runner.db.update_trigger_state) as update:
                start_default_services(runner)

            update.assert_not_called()

    def test_start_default_services_ignores_inactive_network_capability_event(self):
        """Protect start default services ignores inactive network capability event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            job_id = runner.db.record_job("hostscanner 127.0.0.1", None, "finished")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": job_id,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()

    def test_start_default_services_advances_trigger_cursor_past_non_matches(self):
        """Protect start default services advances trigger cursor past non matches behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            inactive_job = runner.db.record_job("hostscanner old", None, "finished")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": inactive_job,
                },
                "hostscanner",
            )
            event = Event.new("job.requested", {"job_id": 7}, "runner")
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_not_called()
            cursor = runner.trigger_event_cursors["runtime.watchdog.network-access-starts-watchdog"]
            self.assertGreater(cursor, 0)

            active_job = runner.db.record_job("hostscanner 127.0.0.1", None, "running")
            runner.db.publish(
                "plugin.capability.used",
                {
                    "commandlet": "hostscanner",
                    "capability": "network.connect",
                    "declared": True,
                    "request_event_id": None,
                    "job_id": active_job,
                },
                "hostscanner",
            )
            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)
            start.assert_called_once_with("watchdog --session-service")
            self.assertGreater(runner.trigger_event_cursors["runtime.watchdog.network-access-starts-watchdog"], cursor)

    def test_trigger_payload_equals_predicate_and_foreground_action(self):
        """Protect trigger payload equals predicate and foreground action behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="dedupe-vulnerabilities",
                    topic="vulnerability.found",
                    action_command="finding_dedupe",
                    action_mode="foreground",
                    payload_equals=(("severity", "high"),),
                )
            ]
            runner.db.publish("vulnerability.found", {"severity": "low"}, "nikto")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_not_called()
            runner.db.publish("vulnerability.found", {"severity": "high"}, "nikto")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_called_once_with("finding_dedupe")

    def test_trigger_background_action_starts_each_matching_event(self):
        """Protect trigger background action starts each matching event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="report-findings",
                    topic="finding.deduped",
                    action_command="finding_report",
                    action_mode="background",
                )
            ]
            first = Event.new("job.requested", {"job_id": 8}, "runner")
            second = Event.new("job.requested", {"job_id": 9}, "runner")
            runner.db.publish("finding.deduped", {"id": "a"}, "finding_dedupe")
            with patch.object(runner, "start_background", return_value=first) as start:
                start_default_services(runner)
            start.assert_called_once_with("finding_report")
            runner.db.publish("finding.deduped", {"id": "b"}, "finding_dedupe")
            with patch.object(runner, "start_background", return_value=second) as start:
                start_default_services(runner)
            start.assert_called_once_with("finding_report")

    def test_provider_scoped_trigger_ids_prevent_cursor_collisions(self):
        """Protect provider scoped trigger IDs prevent cursor collisions behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first_trigger = TriggerSpec(
                name="same-local-name",
                topic="provider.b.event",
                action_command="provider_b_action",
                action_mode="background",
            )
            second_trigger = TriggerSpec(
                name="same-local-name",
                topic="provider.a.event",
                action_command="provider_a_action",
                action_mode="background",
            )
            runner.registry.triggers = []
            runner.registry.trigger_providers.clear()
            runner.registry.add_triggers("provider.a", (second_trigger,))
            runner.registry.add_triggers("provider.b", (first_trigger,))
            runner.db.publish("provider.b.event", {"id": "older"}, "provider_b")
            runner.db.publish("provider.a.event", {"id": "newer"}, "provider_a")
            event = Event.new("job.requested", {"job_id": 10}, "runner")

            with patch.object(runner, "start_background", return_value=event) as start:
                start_default_services(runner)

            start.assert_any_call("provider_a_action")
            start.assert_any_call("provider_b_action")
            self.assertEqual(start.call_count, 2)
            states = {str(row["name"]): row for row in runner.db.trigger_states()}
            self.assertIn("provider.a.same-local-name", states)
            self.assertIn("provider.b.same-local-name", states)

    def test_trigger_suppresses_self_trigger_loop_by_default(self):
        """Protect trigger suppresses self trigger loop by default behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.triggers = [
                TriggerSpec(
                    name="dedupe-loop-guard",
                    topic="finding.deduped",
                    action_command="finding_dedupe",
                    action_mode="foreground",
                )
            ]
            runner.db.publish("finding.deduped", {"id": "a"}, "finding_dedupe")
            with patch.object(runner, "execute") as execute:
                start_default_services(runner)
            execute.assert_not_called()

    def test_shutdown_runner_audits_trigger_disabled(self):
        """Protect shutdown runner audits trigger disabled behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch.object(runner.db, "checkpoint"):
                start_default_services(runner)
                shutdown_runner(runner)
            disabled = runner.db.events_for_topic("framework.trigger.disabled")[0]
            self.assertEqual(disabled.payload["name"], "network-access-starts-watchdog")
            self.assertEqual(disabled.payload["topic"], "plugin.capability.used")


if __name__ == "__main__":
    unittest.main()
