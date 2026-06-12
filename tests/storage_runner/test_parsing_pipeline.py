# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility.

Coverage focus: storage runner parsing pipeline regression behavior.
"""

from tests.storage_runner.support import *  # noqa: F403,F405

class StorageRunnerParsingPipelineTests(unittest.TestCase):
    """Groups regression coverage for storage runner tests split by responsibility."""
    def test_parse_invocation_uses_first_token_as_name(self):
        """Protect parse invocation uses first token as name behavior from regressions."""
        invocation = parse_invocation("hostscanner 127.0.0.1")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])

    def test_plugin_can_stop_pipeline_before_downstream_stage(self):
        """Protect plugin can stop pipeline before downstream stage behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.register_commandlet("test", StopPipelinePlugin(), origin="bundled")
            runner.registry.register_commandlet("test", DownstreamMarkerPlugin(), origin="bundled")

            events = runner.execute("stop_pipeline | downstream_marker")

            self.assertEqual(events, [])
            self.assertTrue(runner.db.events_for_topic("framework.pipeline.stop.requested"))
            stopped = runner.db.events_for_topic("pipeline.stopped")[0]
            self.assertEqual(stopped.payload["reason"], "nothing useful downstream")
            self.assertTrue(runner.db.cancellation_requested(pipeline_id=stopped.pipeline_id))
            self.assertEqual(runner.db.events_for_topic("downstream.marker"), [])

    def test_plugin_pipeline_stop_requires_declared_capability(self):
        """Protect plugin pipeline stop requires declared capability behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.register_commandlet("test", StopPipelineWithoutCapabilityPlugin(), origin="bundled")
            runner.registry.register_commandlet("test", DownstreamMarkerPlugin(), origin="bundled")

            with self.assertRaisesRegex(PermissionError, "framework.pipeline.control"):
                runner.execute("stop_pipeline_undeclared | downstream_marker")

            self.assertTrue(runner.db.events_for_topic("plugin.capability.missing"))
            self.assertEqual(runner.db.events_for_topic("framework.pipeline.stop.requested"), [])
            self.assertEqual(runner.db.events_for_topic("downstream.marker"), [])

    def test_plugin_pipeline_context_does_not_expose_topology(self):
        """Protect plugin pipeline context does not expose topology behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.registry.register_commandlet("test", InspectPipelineApiPlugin(), origin="bundled")

            events = runner.execute("inspect_pipeline_api")

            self.assertEqual(events[0].payload["public"], ["stop"])
            self.assertFalse(events[0].payload["has_context"])
            self.assertFalse(events[0].payload["has_downstream"])
            self.assertFalse(events[0].payload["has_next_commandlet"])
            self.assertFalse(events[0].payload["has_position"])
            self.assertFalse(events[0].payload["has_stage_count"])
            self.assertFalse(events[0].payload["has_stages"])

    def test_parse_pipeline(self):
        """Protect parse pipeline behavior from regressions."""
        pipeline = parse_pipeline("hostscanner 127.0.0.1 | portscanner port=80 &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertFalse(pipeline.commands[0].background)
        self.assertTrue(pipeline.commands[1].background)

    def test_parse_stage_background_pipeline(self):
        """Protect parse stage background pipeline behavior from regressions."""
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 & | portscanner &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.background for command in pipeline.commands], [True, True])
        self.assertEqual(pipeline.commands[0].args, ["192.168.0.1-2"])

    def test_mixed_background_pipeline_preserves_pipe_flow(self):
        """Protect mixed background pipeline preserves pipe flow behavior from regressions."""
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 & | portscanner")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.background for command in pipeline.commands], [True, False])
        self.assertFalse(should_run_stage_processes(pipeline.commands))

    def test_fully_background_pipeline_splits_stages(self):
        """Protect fully background pipeline splits stages behavior from regressions."""
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 & | portscanner &")
        self.assertTrue(should_run_stage_processes(pipeline.commands))

    def test_trailing_background_pipeline_preserves_pipe_flow(self):
        """Protect trailing background pipeline preserves pipe flow behavior from regressions."""
        pipeline = parse_pipeline("hostscanner 192.168.0.1-2 | portscanner &")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.background for command in pipeline.commands], [False, True])
        self.assertFalse(should_run_stage_processes(pipeline.commands))

    def test_parse_attached_background_markers(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1& | portscanner&")
        self.assertTrue(pipeline.background)
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])
        self.assertEqual(pipeline.commands[0].args, ["127.0.0.1"])
        self.assertEqual([command.background for command in pipeline.commands], [True, True])

    def test_parse_framework_context_selectors(self):
        invocation = parse_invocation(
            "portscanner --from step=host-run pipeline=pipe job=7 topic=host.found port=80"
        )
        self.assertEqual(invocation.from_step, "host-run")
        self.assertEqual(invocation.from_pipeline, "pipe")
        self.assertEqual(invocation.from_job, "7")
        self.assertEqual(invocation.from_topic, "host.found")
        self.assertEqual(invocation.args, ["port=80"])

    def test_from_selector_requires_replay_scope(self):
        with self.assertRaisesRegex(ValueError, "topic= only narrows"):
            parse_invocation("portscanner --from topic=host.found port=80")

    def test_parse_invocation_strips_final_unquoted_note(self):
        invocation = parse_invocation("hostscanner 127.0.0.1 note=client approved target")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "client approved target")

    def test_parse_invocation_strips_final_unquoted_name(self):
        invocation = parse_invocation("hostscanner 127.0.0.1 name=localhost sweep")
        self.assertEqual(invocation.name, "hostscanner")
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.display_name, "localhost sweep")

    def test_parse_invocation_preserves_plugin_owned_name_selector(self):
        invocation = parse_invocation("key show name=firm-evidence")
        self.assertEqual(invocation.name, "key")
        self.assertEqual(invocation.args, ["show", "name=firm-evidence"])
        self.assertIsNone(invocation.display_name)

    def test_parse_invocation_strips_quoted_note(self):
        invocation = parse_invocation('hostscanner 127.0.0.1 note="client approved target"')
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "client approved target")

    def test_parse_pipeline_keeps_stage_notes_separate(self):
        pipeline = parse_pipeline("hostscanner 127.0.0.1 note=scope approved | portscanner note=top ports")
        self.assertEqual(pipeline.commands[0].args, ["127.0.0.1"])
        self.assertEqual(pipeline.commands[0].note, "scope approved")
        self.assertEqual(pipeline.commands[1].args, [])
        self.assertEqual(pipeline.commands[1].note, "top ports")

    def test_parse_pipeline_accepts_name_prefix(self):
        pipeline = parse_pipeline("client subnet scan: hostscanner 127.0.0.1 | portscanner")
        self.assertEqual(pipeline.display_name, "client subnet scan")
        self.assertEqual([command.name for command in pipeline.commands], ["hostscanner", "portscanner"])

    def test_parse_pipeline_does_not_treat_url_colon_as_name(self):
        pipeline = parse_pipeline("http_probe http://127.0.0.1")
        self.assertIsNone(pipeline.display_name)
        self.assertEqual(pipeline.commands[0].args, ["http://127.0.0.1"])

    def test_parse_invocation_keeps_background_marker_with_note(self):
        invocation = parse_invocation("hostscanner 127.0.0.1& note=background scan")
        self.assertTrue(invocation.background)
        self.assertEqual(invocation.args, ["127.0.0.1"])
        self.assertEqual(invocation.note, "background scan")

    def test_parse_invocation_expands_variables_outside_single_quotes(self):
        store = VarStore()
        store.set("hostscanner.targets", "127.0.0.1 127.0.0.2")
        store.set("global.target", "example.test")
        def scope(name: str) -> str:
            return name

        unquoted = parse_invocation("hostscanner $targets", varstore=store, command_scope_resolver=scope)
        double_quoted = parse_invocation('hostscanner "$targets"', varstore=store, command_scope_resolver=scope)
        single_quoted = parse_invocation("hostscanner '$targets'", varstore=store, command_scope_resolver=scope)
        global_value = parse_invocation("hostscanner $target", varstore=store, command_scope_resolver=scope)
        self.assertEqual(unquoted.args, ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(double_quoted.args, ["127.0.0.1 127.0.0.2"])
        self.assertEqual(single_quoted.args, ["$targets"])
        self.assertEqual(global_value.args, ["example.test"])
        self.assertEqual(unquoted.variable_expansions, ("hostscanner.targets",))
        self.assertEqual(single_quoted.variable_expansions, ())

    def test_parse_invocation_rejects_unknown_variable(self):
        with self.assertRaisesRegex(ValueError, "unknown variable"):
            parse_invocation("hostscanner $missing", varstore=VarStore())

    def test_parse_save_spec_accepts_encrypt_before_resource(self):
        encrypt, resource = parse_save_spec("--encrypt db=client.sqlite3")
        self.assertTrue(encrypt)
        self.assertEqual(resource, "db=client.sqlite3")
