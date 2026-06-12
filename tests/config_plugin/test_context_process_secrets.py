# ruff: noqa: F403,F405
"""Config/plugin tests split by responsibility.

Coverage focus: config plugin context process secrets regression behavior.
"""

from tests.config_plugin.support import *  # noqa: F403,F405
class ConfigPluginContextProcessSecretTests(unittest.TestCase):
    """Groups regression coverage for config/plugin tests split by responsibility."""
    def test_command_context_process_run_redacts_secret_argv(self):
        """Protect command context process run redacts secret argv behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            secrets = InMemorySecretStore()
            secret_ref = secrets.put("test.password", "supersecret", key=b"k" * 32)
            context = CommandContext(
                db=db,
                source="test",
                _secrets=secrets,
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.secret.resolve", "framework.process.run"),
                },
            )
            password = context.secrets.resolve(secret_ref.ref)
            context.process.run([sys.executable, "-c", "print('ok')", f"password={password}"])
            request = db.events_for_topic("framework.process.run.requested")[0]
            result = db.events_for_topic("process.run")[0]
            warnings = db.events_for_topic("process.secret.argv")
        self.assertNotIn("supersecret", str(request.payload))
        self.assertNotIn("supersecret", str(result.payload))
        self.assertEqual(request.payload["argv"][-1], "password=[REDACTED]")
        self.assertEqual(warnings[0].payload["argv"][-1], "password=[REDACTED]")

    def test_command_context_process_run_audits_redacted_secret_env(self):
        """Protect command context process run audits redacted secret env behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            secrets = InMemorySecretStore()
            secret_ref = secrets.put("test.password", "supersecret", key=b"k" * 32)
            context = CommandContext(
                db=db,
                source="test",
                _secrets=secrets,
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.secret.resolve", "framework.process.run"),
                },
            )
            password = context.secrets.resolve(secret_ref.ref)
            context.process.run([sys.executable, "-c", "print('ok')"], env={"TOOL_PASSWORD": password or ""})
            request = db.events_for_topic("framework.process.run.requested")[0]
        self.assertNotIn("supersecret", str(request.payload))
        self.assertEqual(request.payload["env"]["TOOL_PASSWORD"], "[REDACTED]")
        self.assertEqual(request.payload["secrets"][0]["env"], "TOOL_PASSWORD")
        self.assertEqual(request.payload["secrets"][0]["name"], "test.password")

    def test_command_context_process_run_redacts_secret_output_events(self):
        """Protect command context process run redacts secret output events behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            secrets = InMemorySecretStore()
            secret_ref = secrets.put("test.password", "supersecret", key=b"k" * 32)
            context = CommandContext(
                db=db,
                source="test",
                _secrets=secrets,
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.secret.resolve", "framework.process.run"),
                },
            )
            password = context.secrets.resolve(secret_ref.ref)
            result = context.process.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; print(sys.argv[1]); print(sys.argv[1], file=sys.stderr)",
                    password or "",
                ]
            )
            event = db.events_for_topic("process.run")[0]
            artifact = artifact_store_for_db(db).list(command_run_id="run-1")[0]
        self.assertIn("supersecret", result.stdout)
        self.assertNotIn("supersecret", str(event.payload))
        self.assertNotIn("supersecret", artifact.body.decode())
        self.assertEqual(event.payload["stdout"], "[REDACTED]\n")
        self.assertEqual(event.payload["stderr"], "[REDACTED]\n")

    def test_commandlet_secret_args_are_redacted_with_secret_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            secrets = InMemorySecretStore()
            secret_ref = secrets.put("ssh_probe.password", "supersecret", key=b"k" * 32)
            context = CommandContext(db=db, source="ssh_probe", _secrets=secrets)
            plugin = PluginRegistry.discover().get("ssh_probe")
            redacted, secret_args = redact_commandlet_args(
                context,
                plugin,
                ["127.0.0.1", "--password", secret_ref.ref],
            )
        self.assertEqual(redacted, ["127.0.0.1", "--password", "[REDACTED]"])
        self.assertEqual(secret_args[0]["name"], "ssh_probe.password")
        self.assertEqual(secret_args[0]["option"], "password")

    def test_command_context_events_follow_stops_after_parent_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="listener",
                metadata={
                    "pipeline_id": "pipe-1",
                    "parent_command_run_id": "parent-run",
                    "capabilities": (
                        "db.read:host.found",
                        "db.read:command.run.completed",
                        "db.read:command.run.failed",
                    ),
                },
            )
            db.publish("host.found", {"host": "127.0.0.1"}, "hostscanner", pipeline_id="pipe-1", command_run_id="parent-run")
            db.publish("host.found", {"host": "10.0.0.1"}, "other", pipeline_id="pipe-2", command_run_id="parent-run")
            db.publish("command.run.completed", {"status": "completed"}, "framework", pipeline_id="pipe-1", command_run_id="parent-run")

            events = list(
                context.events.follow(
                    ("host.found",),
                    pipeline_id="pipe-1",
                    until_parent_done=True,
                    idle_interval=0,
                    timeout=1,
                )
            )

        self.assertEqual([event.payload["host"] for event in events], ["127.0.0.1"])

    def test_command_context_process_stream_records_incremental_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={"capabilities": ("framework.process.stream",)},
            )
            chunks = list(
                context.process.stream(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        "import sys; print('out'); print('err', file=sys.stderr)",
                    ]
                )
            )
            started = db.events_for_topic("process.started")
            stdout = db.events_for_topic("process.stdout")
            stderr = db.events_for_topic("process.stderr")
            exited = db.events_for_topic("process.exited")
            used = db.events_for_topic("plugin.capability.used")
        self.assertEqual([chunk.stream for chunk in chunks], ["stdout", "stderr"])
        self.assertEqual(started[0].payload["argv"][0], sys.executable)
        self.assertEqual(stdout[0].payload["text"], "out\n")
        self.assertEqual(stderr[0].payload["text"], "err\n")
        self.assertEqual(exited[0].payload["returncode"], 0)
        self.assertEqual(used[0].payload["capability"], "framework.process.stream")
        self.assertTrue(used[0].payload["declared"])

    def test_command_context_process_stream_redacts_secret_output_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            secrets = InMemorySecretStore()
            secret_ref = secrets.put("test.password", "supersecret", key=b"k" * 32)
            context = CommandContext(
                db=db,
                source="test",
                _secrets=secrets,
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.secret.resolve", "framework.process.stream"),
                },
            )
            password = context.secrets.resolve(secret_ref.ref)
            chunks = list(
                context.process.stream(
                    [
                        sys.executable,
                        "-u",
                        "-c",
                        "import sys; print(sys.argv[1])",
                        password or "",
                    ]
                )
            )
            stdout = db.events_for_topic("process.stdout")
        self.assertEqual(chunks[0].text, "supersecret\n")
        self.assertEqual(stdout[0].payload["text"], "[REDACTED]\n")
        self.assertNotIn("supersecret", str(stdout[0].payload))
