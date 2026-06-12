# ruff: noqa: F403,F405
"""Config/plugin tests split by responsibility.

Coverage focus: config plugin context capabilities regression behavior.
"""

from unittest.mock import patch

from tests.config_plugin.support import *  # noqa: F403,F405
class ConfigPluginContextCapabilityTests(unittest.TestCase):
    """Groups regression coverage for config/plugin tests split by responsibility."""
    def test_command_context_metadata_default(self):
        """Protect command context metadata default behavior from regressions."""
        context = CommandContext(db=None, source="test")
        self.assertEqual(context.metadata, {})

    def test_command_context_exposes_scoped_vars(self):
        """Protect command context exposes scoped vars behavior from regressions."""
        context = CommandContext(db=None, source="test")
        context.vars.set("value", "abc")
        self.assertEqual(context.vars.get("value"), "abc")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other/value")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other.value")

    def test_command_context_does_not_expose_raw_varstore(self):
        """Protect command context does not expose raw varstore behavior from regressions."""
        store = VarStore()
        store.set("other.secret", "hidden")
        context = CommandContext(db=None, source="test", _varstore=store)
        self.assertFalse(hasattr(context, "_varstore"))
        self.assertFalse(hasattr(context.vars, "store"))
        self.assertIsNone(context.vars.get("secret"))

    def test_command_context_vars_prefer_run_snapshot(self):
        """Protect command context vars prefer run snapshot behavior from regressions."""
        store = VarStore()
        store.set("test.value", "session")
        store.set("global.proxy", "session-proxy")
        context = CommandContext(
            db=None,
            source="test",
            _varstore=store,
            metadata={
                "run_vars": {
                    "test.value": "run",
                    "global.proxy": "run-proxy",
                }
            },
        )
        self.assertEqual(context.vars.get("value"), "run")
        self.assertEqual(context.vars.get_global("proxy"), "run-proxy")

    def test_command_context_resolves_secret_references(self):
        """Protect command context resolves secret references behavior from regressions."""
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
                    "capabilities": ("framework.secret.resolve",),
                },
            )
            self.assertEqual(context.secrets.resolve(secret_ref.ref), "supersecret")
            self.assertEqual(context.secrets.resolve("plaintext"), "plaintext")
            self.assertTrue(context.secrets.is_secret_ref(secret_ref.ref))
            fingerprint = context.secrets.fingerprint(secret_ref.ref)
            self.assertIsNotNone(fingerprint)
            assert fingerprint is not None
            self.assertTrue(fingerprint.startswith("hmac-sha256:"))
            used = db.events_for_topic("plugin.capability.used")
            self.assertEqual(used[0].payload["capability"], "framework.secret.resolve")
            self.assertTrue(used[0].payload["declared"])

    def test_command_context_dedupes_repeated_capability_audit(self):
        """Protect command context dedupes repeated capability audit behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="portscanner",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("network.connect",),
                },
            )
            context.audit_capability("network.connect")
            context.audit_capability("network.connect")
            used = db.events_for_topic("plugin.capability.used")
            self.assertEqual(len(used), 1)
            self.assertEqual(used[0].payload["capability"], "network.connect")

    def test_command_context_keeps_request_specific_capability_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.console.output",),
                },
            )
            context.audit_capability("framework.console.output", request_event_id=1)
            context.audit_capability("framework.console.output", request_event_id=2)
            used = db.events_for_topic("plugin.capability.used")
            self.assertEqual(len(used), 2)
            self.assertEqual([event.payload["request_event_id"] for event in used], [1, 2])

    def test_command_context_enforces_database_action_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="ports",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("db.read:port.open", "db.write:port.open"),
                    "database_actions": ("view",),
                },
            )
            context.audit_capability("db.read:port.open")
            with self.assertRaisesRegex(PermissionError, "database action policy denies db.write:port.open"):
                context.audit_capability("db.write:port.open")

    def test_command_context_alert_prints_without_database(self):
        context = CommandContext(db=None, source="test", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            context.alert("hello")
        self.assertEqual(output.getvalue(), "test <run-1>: hello\n")

    def test_command_context_alert_requests_framework_event_when_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"command_run_id": "run-1"})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                context.alert("hello", silent=True)
            requests = db.events_for_topic("framework.console.alert.requested")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(requests[0].payload["message"], "hello")
        self.assertTrue(requests[0].payload["silent"])
        self.assertEqual(requests[0].command_run_id, "run-1")

    def test_command_context_output_requests_framework_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"command_run_id": "run-1"})
            context.output("hello", end="")
            requests = db.events_for_topic("framework.console.output.requested")
        self.assertEqual(requests[0].payload["text"], "hello")
        self.assertEqual(requests[0].payload["end"], "")
        self.assertEqual(requests[0].command_run_id, "run-1")

    def test_command_context_process_run_records_request_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.process.run",),
                },
            )
            result = context.process.run([sys.executable, "-c", "print('hello')"])
            requests = db.events_for_topic("framework.process.run.requested")
            results = db.events_for_topic("process.run")
            used = db.events_for_topic("plugin.capability.used")
            artifacts = artifact_store_for_db(db).list(command_run_id="run-1")
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "hello\n")
        self.assertEqual(requests[0].payload["argv"], [sys.executable, "-c", "print('hello')"])
        self.assertEqual(results[0].payload["returncode"], 0)
        self.assertEqual(results[0].payload["request_event_id"], requests[0].id)
        self.assertEqual(results[0].payload["artifact_id"], artifacts[0].artifact_id)
        self.assertIn("stdout:\nhello\n", artifacts[0].body.decode())
        self.assertEqual(used[0].payload["capability"], "framework.process.run")
        self.assertTrue(used[0].payload["declared"])

    def test_command_context_events_publish_and_read_schema_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="test",
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("db.write:port.open",),
                },
            )
            context.events.publish_object(OpenPort("192.0.2.10", 443, "tcp", service="https"))
            events = db.events_for_topic("port.open")

        self.assertEqual(events[0].payload["host"], "192.0.2.10")
        self.assertEqual(context.events.objects(events, OpenPort), (OpenPort("192.0.2.10", 443, "tcp", service="https"),))

    def test_context_policy_filter_logs_only_pruned_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.policy.network.allow", "192.0.2.0/24")
            context = CommandContext(db=db, source="test", _varstore=store)

            allowed = context.policy.filter_network_targets(["192.0.2.10", "198.51.100.10"])

            self.assertEqual(allowed, ("192.0.2.10",))
            policy = db.events_for_topic("policy.evaluated")[0]
            self.assertEqual(policy.payload["decision"], "warn")
            self.assertEqual(policy.payload["before"], {"targets": ["192.0.2.10", "198.51.100.10"]})
            self.assertEqual(policy.payload["after"], {"targets": ["192.0.2.10"]})
            self.assertIn("198.51.100.10 is outside allowed network scope", policy.payload["warnings"])

    def test_context_policy_allowed_targets_do_not_emit_policy_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.policy.network.allow", "192.0.2.0/24")
            context = CommandContext(db=db, source="test", _varstore=store)

            allowed = context.policy.filter_network_targets(["192.0.2.10"])

            self.assertEqual(allowed, ("192.0.2.10",))
            self.assertEqual(db.events_for_topic("policy.evaluated"), [])

    def test_context_policy_resolves_hostnames_for_allow_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.policy.network.allow", "192.0.2.0/24")
            context = CommandContext(db=db, source="test", _varstore=store)

            with patch("bywaf.plugin.services.network_policy.resolve_target", return_value=("192.0.2.55",)):
                allowed = context.policy.filter_network_targets(["example.test"])

            self.assertEqual(allowed, ("example.test",))
            self.assertEqual(db.events_for_topic("policy.evaluated"), [])

    def test_command_context_process_run_audits_missing_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test")
            context.process.run([sys.executable, "-c", "print('hello')"])
            missing = db.events_for_topic("plugin.capability.missing")
        self.assertEqual(missing[0].payload["capability"], "framework.process.run")

    def test_process_run_enforce_mode_requires_artifact_write_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.capabilities.mode", "enforce")
            marker = Path(tmp, "marker")
            context = CommandContext(
                db=db,
                source="test",
                _varstore=store,
                metadata={
                    "command_run_id": "run-1",
                    "capabilities": ("framework.process.run",),
                },
            )

            with self.assertRaisesRegex(PermissionError, "undeclared capability: artifact.write"):
                context.process.run(
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path(__import__('sys').argv[1]).write_text('ran')",
                        str(marker),
                    ]
                )

            missing = db.events_for_topic("plugin.capability.missing")
            results = db.events_for_topic("process.run")
            artifacts = artifact_store_for_db(db).list(command_run_id="run-1")
        self.assertFalse(marker.exists())
        self.assertEqual(missing[0].payload["capability"], "artifact.write")
        self.assertEqual(results, [])
        self.assertEqual(artifacts, [])

    def test_capability_enforce_mode_denies_missing_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.capabilities.mode", "enforce")
            context = CommandContext(db=db, source="test", _varstore=store)

            with self.assertRaisesRegex(PermissionError, "undeclared capability"):
                context.output("hello")

            missing = db.events_for_topic("plugin.capability.missing")
            requests = db.events_for_topic("framework.console.output.requested")
        self.assertEqual(missing[0].payload["capability"], "framework.console.output")
        self.assertEqual(requests, [])

    def test_capability_mode_uses_context_default_when_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test", metadata={"capability_mode": "enforce"})

            with self.assertRaisesRegex(PermissionError, "undeclared capability"):
                context.output("hello")

            missing = db.events_for_topic("plugin.capability.missing")
        self.assertEqual(missing[0].payload["capability"], "framework.console.output")

    def test_global_capability_mode_overrides_context_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.capabilities.mode", "audit")
            context = CommandContext(db=db, source="test", _varstore=store, metadata={"capability_mode": "enforce"})

            context.output("hello")

            missing = db.events_for_topic("plugin.capability.missing")
            requests = db.events_for_topic("framework.console.output.requested")
        self.assertEqual(missing[0].payload["capability"], "framework.console.output")
        self.assertEqual(len(requests), 1)

    def test_capability_off_mode_suppresses_capability_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            store = VarStore()
            store.set("global.capabilities.mode", "off")
            context = CommandContext(db=db, source="test", _varstore=store)

            context.output("hello")

            self.assertEqual(db.events_for_topic("plugin.capability.used"), [])
            self.assertEqual(db.events_for_topic("plugin.capability.missing"), [])
