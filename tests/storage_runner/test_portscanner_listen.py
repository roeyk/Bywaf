# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility.

Coverage focus: storage runner portscanner listen regression behavior.
"""

from tests.storage_runner.support import *  # noqa: F403,F405

class StorageRunnerPortscannerListenTests(unittest.TestCase):
    """Groups regression coverage for storage runner tests split by responsibility."""
    def test_portscanner_listen_scopes_to_upstream_command_run(self):
        """Protect portscanner listen scopes to upstream command run behavior from regressions."""
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
        """Protect portscanner listen requires upstream pipeline scope behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(EventStore(Path(tmp, "db.sqlite3")), source="portscanner")
            with self.assertRaisesRegex(ValueError, "pipeline scope"):
                list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))

    def test_portscanner_listen_prunes_out_of_scope_upstream_hosts(self):
        """Protect portscanner listen prunes out of scope upstream hosts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            db.publish(
                "host.found",
                {"host": "198.51.100.1"},
                "hostscanner",
                pipeline_id="pipe-1",
                command_run_id="upstream-1",
            )
            varstore = VarStore()
            varstore.set("global.policy.network.allow", "192.0.2.0/24")
            context = CommandContext(
                db,
                source="portscanner",
                _varstore=varstore,
                metadata={
                    "pipeline_id": "pipe-1",
                    "command_run_id": "port-1",
                    "parent_command_run_id": "upstream-1",
                    "input_high_watermark": 0,
                },
            )
            with patch("bywaf.plugins.network.portscanner.scan_open_ports") as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = list(PortScanner().run(context, ["--listen", "--listen-timeout", "0.01"], []))
            self.assertEqual(events, [])
            scan.assert_not_called()
            policy = db.events_for_topic("policy.evaluated")[0]
            self.assertEqual(policy.payload["before"], {"targets": ["198.51.100.1"]})
            self.assertEqual(policy.payload["after"], {"targets": []})

    def test_background_portscanner_auto_listens_to_upstream_scope(self):
        """Protect background portscanner auto listens to upstream scope behavior from regressions."""
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
        """Protect pipeline portscanner auto listens to upstream scope behavior from regressions."""
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
