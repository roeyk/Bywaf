# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility."""

from tests.storage_runner.support import *  # noqa: F403,F405


class StorageRunnerHostscannerRuntimeTests(unittest.TestCase):
    """Runner integration tests centered on hostscanner and runtime metadata.

    The suite patches scanner backends but runs through `Runner.execute()` so
    command parsing, variable expansion, notes, names, capabilities, and event
    persistence are exercised together.
    """

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
            capabilities = {
                event.payload["capability"]: event.payload["declared"]
                for event in runner.db.events_for_topic("plugin.capability.used")
                if event.source == "hostscanner"
            }
            self.assertTrue(capabilities["network.connect"])
            self.assertTrue(capabilities["framework.console.alert"])
            self.assertTrue(capabilities["db.write:host.found"])

    def test_hostscanner_uses_targets_variable_when_cli_target_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1")
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            discover.assert_called_once_with("127.0.0.1", "-sn")

    def test_hostscanner_accepts_host_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner host=127.0.0.1")
            self.assertEqual(events[0].payload["host"], "127.0.0.1")
            discover.assert_called_once_with("127.0.0.1", "-sn")

    def test_framework_expands_and_audits_dollar_variables(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1 127.0.0.2")
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner $targets")
            discover.assert_called_once_with("127.0.0.1 127.0.0.2", "-sn")
            # Variable expansion is recorded as framework evidence attached to
            # the same command run as the plugin event.
            expansions = runner.db.events_for_topic("framework.variable.expanded")
            self.assertEqual(expansions[0].payload["variables"], ["discovery/hostscanner.targets"])
            self.assertEqual(expansions[0].command_run_id, events[0].command_run_id)

    def test_hostscanner_cli_target_overrides_targets_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.0.2.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                runner.registry.varstore.set("discovery/hostscanner.targets", "127.0.0.1")
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.0.2.1")
            discover.assert_called_once_with("192.0.2.1", "-sn")

    def test_framework_note_attaches_to_command_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 note=client approved target")
            note = runner.db.events_for_topic("note.attached")[0]
            self.assertEqual(note.payload["note"], "client approved target")
            self.assertEqual(note.payload["commandlet"], "hostscanner")
            self.assertEqual(note.command_run_id, events[0].command_run_id)
            self.assertEqual(note.pipeline_id, events[0].pipeline_id)
            self.assertEqual(note.payload["job_id"], runner.db.job()[0]["id"])

    def test_framework_note_attaches_to_each_pipeline_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
                patch(
                    "bywaf.plugins.network.portscanner.scan_open_ports",
                    return_value=[NmapPort("127.0.0.1", 80, "tcp", "open", "http")],
                ),
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute(
                        "hostscanner 127.0.0.1 note=scope approved | portscanner note=top ports"
                    )
            notes = runner.db.events_for_topic("note.attached")
            # Inline note= values are stage-local in pipelines, not copied from
            # one commandlet to the next.
            self.assertEqual([note.payload["note"] for note in notes], ["scope approved", "top ports"])
            self.assertEqual(notes[0].command_run_id, events[0].command_run_id)
            self.assertEqual(notes[1].command_run_id, events[-1].command_run_id)

    def test_inline_names_attach_to_pipeline_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("client subnet scan: hostscanner 127.0.0.1 name=localhost sweep")
            names = runner.db.runtime_names()
            # Prefix labels name the pipeline, while trailing name= labels name
            # the individual command run.
            pipeline_id = events[0].pipeline_id
            self.assertIsNotNone(pipeline_id)
            assert pipeline_id is not None
            self.assertEqual(names[("pipeline", pipeline_id)], "client subnet scan")
            self.assertEqual(names[("run", events[0].command_run_id or "")], "localhost sweep")

    def test_name_command_assigns_posthoc_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("name step=1 localhost sweep")
                process_framework_requests(runner, ShellState())
                runner.execute("name step=1")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.runtime_names()[("run", "run-1")], "localhost sweep")
            self.assertIn("step=run-1 name=localhost sweep", output.getvalue())

    def test_name_command_accepts_text_keyed_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="run-1")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("name step=run-1 text=localhost sweep")
                process_framework_requests(runner, ShellState())
            self.assertEqual(runner.db.runtime_names()[("run", "run-1")], "localhost sweep")

    def test_at_file_lines_expands_before_commandlet_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp, "targets.txt")
            targets.write_text("127.0.0.1\n127.0.0.2\n\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner @lines:{targets}")
            discover.assert_called_once_with("127.0.0.1 127.0.0.2", "-sn")
            # @lines expansion emits provenance so the original file input can
            # be audited separately from the expanded command arguments.
            expansion = runner.db.events_for_topic("framework.argument.expanded")[0]
            self.assertEqual(expansion.payload["mode"], "lines")
            self.assertEqual(expansion.payload["produced"], 2)

    @unittest.skipUnless(sqlcipher_available(), "sqlcipher3-binary is not installed")
    def test_at_file_expansion_attaches_input_file_when_artifacts_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp, "targets.txt")
            targets.write_text("127.0.0.1\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"), encrypted=True, passphrase="secret")
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner @lines:{targets}")
            expansion = runner.db.events_for_topic("framework.argument.expanded")[0]
            self.assertIn("artifact_id", expansion.payload)
            artifacts = artifact_store_for_db(runner.db).list(command_run_id=expansion.command_run_id)
            self.assertEqual(artifacts[0].body, b"127.0.0.1\n")

    def test_at_file_double_at_escapes_literal_at(self):
        values, expansion = expand_at_file_arg("@@literal")
        self.assertEqual(values, ["@literal"])
        self.assertIsNone(expansion)

    def test_at_file_text_expands_as_one_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "value.txt")
            path.write_text("one\ntwo\n")
            values, expansion = expand_at_file_arg(f"@{path}")
        self.assertEqual(values, ["one\ntwo\n"])
        if expansion is None:
            self.fail("expected at-file expansion metadata")
        self.assertEqual(expansion.produced, 1)

    def test_note_command_shows_run_notes_with_timestamp_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1 note=client approved target")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note step=1")
                process_framework_requests(runner, ShellState())
            line = output.getvalue().splitlines()[-1]
            self.assertRegex(line, r"^\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("client approved target", line)
            self.assertIn(f"step={events[0].command_run_id}", line)

    def test_note_command_saves_job_notes_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "notes.txt")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 127.0.0.1 note=file export note")
            job_id = runner.db.job()[0]["id"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute(f"note job={job_id} file={path}")
                process_framework_requests(runner, ShellState())
            text = path.read_text()
            self.assertRegex(text, r"^\d{8} \d{2}:\d{2}:\d{2} [A-Z]+")
            self.assertIn("file export note", text)
            self.assertIn(f"saved 1 notes to {path}", output.getvalue())

    def test_note_add_appends_multiple_run_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 127.0.0.1 note=initial note")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute("note add step=1 text=second note")
                process_framework_requests(runner, ShellState())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note step=1")
                process_framework_requests(runner, ShellState())
            lines = [line for line in output.getvalue().splitlines() if "step=" in line]
            self.assertEqual(len(lines), 2)
            self.assertIn("initial note", lines[0])
            self.assertIn("second note", lines[1])

    def test_note_add_reads_text_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            note_file = Path(tmp, "note.txt")
            note_file.write_text("file-backed posthoc note\n")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.record_job("manual", None, "finished")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"note add job=1 file={note_file}")
                process_framework_requests(runner, ShellState())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("note job=1")
                process_framework_requests(runner, ShellState())
            self.assertIn("file-backed posthoc note", output.getvalue())

    def test_foreground_command_records_job_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner 127.0.0.1")
            self.assertEqual([event.topic for event in events], ["host.found"])
            # Foreground execution still travels through the same job lifecycle
            # machinery used by background commands.
            topics = runner.db.topics()
            self.assertIn("job.requested", topics)
            self.assertIn("job.claimed", topics)
            self.assertIn("job.started", topics)
            self.assertIn("job.finished", topics)
            self.assertEqual(runner.db.job()[0]["status"], "finished")

    def test_hostscanner_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="hostscanner", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["127.0.0.1"]),
            contextlib.redirect_stdout(output),
        ):
            events = list(HostScanner().run(context, ["-s", "127.0.0.1"], []))
        self.assertEqual(events[0]["host"], "127.0.0.1")
        # The silent flag is a plugin-level display control; the structured
        # host event is still yielded for persistence.
        self.assertEqual(output.getvalue(), "")

    def test_hostscanner_expands_range_before_nmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                return_value=["192.168.0.1"],
            ) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-2")
            # Range shorthand is normalized before the backend adapter sees
            # the target string.
            discover.assert_called_once_with("192.168.0.1 192.168.0.2", "-sn")

    def test_hostscanner_resolves_name_before_nmap(self):
        # Duplicate DNS answers are common; the policy layer should preserve
        # order while removing repeats before scanner invocation.
        address_info = [
            (2, 1, 6, "", ("203.0.113.10", 0)),
            (2, 1, 6, "", ("203.0.113.11", 0)),
            (2, 1, 6, "", ("203.0.113.10", 0)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch(
                    "bywaf.policy.socket.getaddrinfo",
                    return_value=address_info,
                ) as getaddrinfo,
                patch(
                    "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                    return_value=["203.0.113.10"],
                ) as discover,
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    events = runner.execute("hostscanner example.test")
            getaddrinfo.assert_called_once_with("example.test", None, type=socket.SOCK_STREAM)
            discover.assert_called_once_with("203.0.113.10 203.0.113.11", "-sn")
            host_events = [event for event in events if event.topic == "host.found"]
            self.assertEqual(host_events[0].payload["host"], "203.0.113.10")
            self.assertEqual(host_events[0].payload["name"], "example.test")
            # Resolution evidence is stored separately from the host.found
            # events so reports can explain how names became addresses.
            resolved = runner.db.events_for_topic("name.resolved")
            self.assertEqual([event.payload["name"] for event in resolved], ["example.test", "example.test"])
            self.assertEqual([event.payload["host"] for event in resolved], ["203.0.113.10", "203.0.113.11"])

    def test_hostscanner_rejects_unresolved_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "bywaf.policy.socket.getaddrinfo",
                side_effect=socket.gaierror,
            ):
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with self.assertRaisesRegex(ValueError, "could not resolve host: missing.test"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        runner.execute("hostscanner missing.test")

    def test_hostscanner_except_removes_targets_before_nmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1-3 except=192.168.0.2,192.168.0.3")
            # Exclusion filtering is applied after range expansion and before
            # invoking nmap, which keeps rejected targets out of backend logs.
            discover.assert_called_once_with("192.168.0.1", "-sn")

    def test_hostscanner_except_supports_at_file_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            excluded = Path(tmp, "excluded.txt")
            excluded.write_text("192.168.0.2\n")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                runner = make_runner(Path(tmp, "db.sqlite3"))
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute(f"hostscanner 192.168.0.1-2 except=@lines:{excluded}")
            discover.assert_called_once_with("192.168.0.1", "-sn")

    def test_hostscanner_plan_shows_intended_targets_without_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with (
                patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts") as discover,
                contextlib.redirect_stdout(output),
            ):
                events = runner.execute("hostscanner 192.168.0.1-2 --test")
                process_framework_requests(runner, ShellState())
            self.assertEqual(events, [])
            discover.assert_not_called()
            # --test is a dry-run path: it produces plan/policy evidence but
            # no scanner side effects and no discovered host events.
            self.assertIn("Plan: scan-hosts", output.getvalue())
            self.assertEqual(runner.db.events_for_topic("plan.requested")[0].payload["summary"], "Scan 2 host target(s) with nmap arguments '-sn'.")
            self.assertEqual(runner.db.events_for_topic("policy.evaluated")[0].payload["decision"], "allow")

    def test_hostscanner_plan_yes_applies_prune_repair_and_audits_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.varstore.set("global.policy.network.allow", "192.168.0.0/24")
            with patch("bywaf.plugins.discovery.hostscanner.discover_live_hosts", return_value=["192.168.0.1"]) as discover:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.execute("hostscanner 192.168.0.1 10.0.0.1 --yes")
            discover.assert_called_once_with("192.168.0.1", "-sn")
            self.assertEqual(runner.db.events_for_topic("plan.approved")[0].payload["approval_method"], "cli-yes")
            # --yes authorizes the framework's scope repair instead of making
            # the plugin scan an out-of-policy target.
            repair = runner.db.events_for_topic("plan.repair.applied")[0]
            self.assertEqual(repair.payload["repair"], "prune-out-of-scope")
            self.assertTrue(repair.payload["approved_by"])

    def test_expand_targets_enforces_limit(self):
        with self.assertRaisesRegex(ValueError, "exceeds limit"):
            expand_targets(["192.168.0.1-3"], 2)
