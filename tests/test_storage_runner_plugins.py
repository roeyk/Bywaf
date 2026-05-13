from pathlib import Path
import contextlib
import io
import os
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
from bywaf.db import EventStore, Subscription
from bywaf.db import database_appears_encrypted, sqlcipher_available
from bywaf.nmap_backend import NmapPort
from bywaf.plugins.discovery.hostscanner import HostScanner
from bywaf.plugins.discovery.hostscanner import expand_targets
from bywaf.plugins.network.portscanner import PortScanner
from bywaf.plugins.storage.db import encrypt_active_database
from bywaf.plugin import CommandContext
from bywaf.runner import parse_invocation, parse_pipeline, run_background_job



class StorageRunnerPluginTests(unittest.TestCase):
    def test_parse_invocation_uses_first_token_as_name(self):
        invocation = parse_invocation("hostscanner 127.0.0.1")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])

    def test_parse_pipeline(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1 | portscanner --ports 80 &")
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
            "portscanner --from-run host-run --from-pipeline pipe --from-topic host.found --ports 80"
        )
        self.assertEqual(invocation.from_run, "host-run")
        self.assertEqual(invocation.from_pipeline, "pipe")
        self.assertEqual(invocation.from_topic, "host.found")
        self.assertEqual(invocation.args, ["--ports", "80"])

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
            self.assertIn("events=1", text)

    def test_db_new_file_creates_and_switches_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertEqual(runner.db.table_counts()["events"], 1)
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested")[0].source, "db")
            self.assertEqual(EventStore(first).table_counts()["events"], 1)

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
            self.assertEqual(runner.db.table_counts()["events"], 1)
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
            self.assertEqual(runner.db.jobs()[0]["status"], "finished")

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
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-2")
            discover.assert_called_once_with("192.168.0.1 192.168.0.2", "-sn")

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
                    events = runner.execute("hostscanner 127.0.0.1 | portscanner --ports 8080")
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
                    events = runner.execute("portscanner --from-run host-run --ports 80")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
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
            with self.assertRaisesRegex(ValueError, "must be used after an upstream"):
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

    def test_background_command_records_job_and_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            with patch("bywaf.nmap_backend.load_backend", return_value=("fake", FakeNmapModule())):
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
            self.assertIn("job.claimed", topics)
            self.assertIn("job.started", topics)
            self.assertIn("job.finished", topics)

    def test_background_job_preserves_attached_stage_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with patch("bywaf.runner.mp.Process") as process_cls:
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
        run_background_job(str(missing_path), None, 1, "job list", "pipeline-test", ())

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
