# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility.

Coverage focus: storage runner portscanner core regression behavior.
"""

from tests.storage_runner.support import *  # noqa: F403,F405

class StorageRunnerPortscannerCoreTests(unittest.TestCase):
    """Groups regression coverage for storage runner tests split by responsibility."""
    def test_pipeline_scans_open_local_port(self):
        """Protect pipeline scans open local port behavior from regressions."""
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

    def test_traceroute_pipeline_scans_original_target_not_route_hops(self):
        """Protect traceroute pipeline scans original target not route hops behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch(
                    "bywaf.plugins.network.traceroute.run_traceroute",
                    return_value=type("TraceResult", (), {"stdout": " 1  router (192.0.2.1)  1.0 ms\n", "ok": True})(),
                ),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.10", 80, "tcp", "open", "http")],
                ) as scan,
                contextlib.redirect_stdout(output),
            ):
                events = runner.execute("traceroute 192.0.2.10 | portscanner port=80")
                process_framework_requests(runner, ShellState())
            self.assertEqual(scan.call_args.args[0], ["192.0.2.10"])
            self.assertEqual([event.topic for event in events if event.topic == "network.route.hop"], ["network.route.hop"])
            self.assertEqual([event.topic for event in events if event.topic == "port.open"], ["port.open"])

    def test_traceroute_prints_route_table(self):
        """Protect traceroute prints route table behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch(
                    "bywaf.plugins.network.traceroute.run_traceroute",
                    return_value=type("TraceResult", (), {"stdout": " 1  router (192.0.2.1)  1.0 ms\n", "ok": True})(),
                ),
                contextlib.redirect_stdout(output),
            ):
                events = runner.execute("traceroute 192.0.2.10")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("Traceroute: 192.0.2.10", text)
            self.assertIn("192.0.2.1", text)
            self.assertEqual([event.topic for event in events if event.topic == "network.route.hop"], ["network.route.hop"])

    def test_background_pipeline_with_single_marker_preserves_stage_output(self):
        """Protect background pipeline with single marker preserves stage output behavior from regressions."""
        command_line = "hostscanner 127.0.0.1 & | portscanner port=8080"
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "db.sqlite3"))
            job_id = db.record_job(command_line, None, "queued")
            pipeline = parse_pipeline(command_line)
            stages = prepare_stage_runs(pipeline.commands)
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
                contextlib.redirect_stdout(io.StringIO()),
            ):
                run_background_job(str(db.path), None, job_id, command_line, "pipeline-test", stages)
            ports = db.events_for_topic("port.open")
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports[0].payload["host"], "127.0.0.1")
            self.assertEqual(ports[0].payload["port"], 8080)

    def test_portscanner_does_not_emit_events_for_closed_scanned_ports(self):
        """Protect portscanner does not emit events for closed scanned ports behavior from regressions."""
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
        """Protect portscanner promotes telnet open candidate behavior from regressions."""
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
            self.assertEqual(candidates[0].payload["confidence_basis"], "service_indicator")

    def test_portscanner_promotes_telnet_on_nonstandard_port_from_service_detection(self):
        """Protect portscanner promotes telnet on nonstandard port from service detection behavior from regressions."""
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
            self.assertEqual(candidates[0].payload["confidence_basis"], "service_indicator")

    def test_portscanner_default_telnet_port_without_service_detection_is_medium_confidence(self):
        """Protect portscanner default telnet port without service detection is medium confidence behavior from regressions."""
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
            self.assertEqual(candidates[0].payload["confidence_basis"], "port_indicator")
            self.assertIn("confirm service identity", candidates[0].payload["evidence"])

    def test_commandlet_can_use_events_from_prior_run(self):
        """Protect commandlet can use events from prior run behavior from regressions."""
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
        """Protect commandlet can use events from prior job behavior from regressions."""
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
        """Protect portscanner port variable is default but CLI overrides behavior from regressions."""
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
        """Protect portscanner accepts key value host list and port behavior from regressions."""
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

    def test_portscanner_prunes_explicit_out_of_scope_hosts_before_nmap(self):
        """Protect portscanner prunes explicit out of scope hosts before nmap behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.policy.network.allow", "192.0.2.0/24")
            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                return_value=[NmapPort("192.0.2.10", 80, "tcp", "open")],
            ) as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner 192.0.2.10 198.51.100.10 port=80")
            self.assertEqual(scan.call_args.args[0], ["192.0.2.10"])
            self.assertEqual(events[0].payload["host"], "192.0.2.10")
            policy = runner.db.events_for_topic("policy.evaluated")[0]
            self.assertEqual(policy.payload["decision"], "warn")
            self.assertEqual(policy.payload["after"], {"targets": ["192.0.2.10"]})
            self.assertIn("198.51.100.10 is outside allowed network scope", policy.payload["warnings"])

    def test_portscanner_skips_nmap_when_policy_prunes_all_explicit_hosts(self):
        """Protect portscanner skips nmap when policy prunes all explicit hosts behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.policy.network.allow", "192.0.2.0/24")
            with patch("bywaf.plugins.network.portscanner.scan_open_ports") as scan:
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("portscanner 198.51.100.10 port=80")
            scan.assert_not_called()
            self.assertEqual(events, [])
            policy = runner.db.events_for_topic("policy.evaluated")[0]
            self.assertEqual(policy.payload["before"], {"targets": ["198.51.100.10"]})
            self.assertEqual(policy.payload["after"], {"targets": []})

    def test_portscanner_keeps_cidr_and_ip_range_targets_unresolved(self):
        """Protect portscanner keeps cidr and IP range targets unresolved behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugin.services.network_policy.resolve_target", side_effect=AssertionError("should not resolve IP ranges")),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("192.0.2.10", 80, "tcp", "open")],
                ) as scan,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("portscanner host=192.0.2.0/24 192.0.3.1-5 port=80")
            self.assertCountEqual(scan.call_args.args[0], ["192.0.2.0/24", "192.0.3.1-5"])

    def test_portscanner_accepts_singular_host_and_records_resolution(self):
        """Protect portscanner accepts singular host and records resolution behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugin.services.network_policy.resolve_target", return_value=("192.0.2.55",)),
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
            self.assertEqual(resolved[0].payload["host"], "192.0.2.55")

    def test_portscanner_filters_resolved_addresses_for_ipv4_arguments(self):
        """Protect portscanner filters resolved addresses for ipv4 arguments behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugin.services.network_policy.resolve_target", return_value=("192.0.2.55", "2001:db8::55")),
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
            self.assertEqual(resolved[0].payload["host"], "192.0.2.55")

    def test_portscanner_filters_resolved_addresses_for_ipv6_arguments(self):
        """Protect portscanner filters resolved addresses for ipv6 arguments behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugin.services.network_policy.resolve_target", return_value=("192.0.2.55", "2001:db8::55")),
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
            self.assertEqual(resolved[0].payload["host"], "2001:db8::55")

    def test_portscanner_except_skips_hosts(self):
        """Protect portscanner except skips hosts behavior from regressions."""
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
        """Protect portscanner silent suppresses alert behavior from regressions."""
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
        """Protect portscanner quiet alias suppresses alert behavior from regressions."""
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
