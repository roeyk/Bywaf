"""Tests for config plugin behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from bywaf.config import Settings, default_settings
from bywaf.db import EventStore
from bywaf.plugin import (
    CommandContext,
    CommandletBase,
    argument,
    commandlet,
    format_table,
    option,
)
from bywaf.plugin_process import normalize_argv
from bywaf.secrets import InMemorySecretStore
from bywaf.messages import Host, Progress
from bywaf.registry import PluginRegistry
from bywaf.runner import redact_commandlet_args
from bywaf.runner.context import effective_run_vars
from bywaf.specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from bywaf.varstore import ScopedVarStore, VarStore


class ConfigPluginTests(unittest.TestCase):
    def test_default_settings(self):
        settings = default_settings()
        self.assertIsInstance(settings, Settings)
        self.assertEqual(settings.database.as_posix(), ".bywaf/bywaf.sqlite3")
        self.assertEqual(settings.config.as_posix(), ".bywaf/config.toml")
        self.assertEqual(settings.history.as_posix(), ".bywaf/history.bywaf")
        self.assertEqual(settings.plugin_dir.as_posix(), ".bywaf/plugins")
        self.assertEqual(settings.script_dir.as_posix(), ".bywaf/scripts")
        self.assertEqual(settings.database_dir.as_posix(), ".bywaf/db")
        self.assertEqual(settings.config_dir.as_posix(), ".bywaf/config")

    def test_option_spec_defaults(self):
        option = OptionSpec("ports", "ports to scan")
        self.assertEqual(option.choices, ())
        self.assertFalse(option.secret)

    def test_command_spec_defaults(self):
        spec = CommandSpec("name", "description")
        self.assertEqual(spec.options, ())
        self.assertEqual(spec.arguments, ())
        self.assertEqual(spec.emits, ())

    def test_argument_spec_defaults(self):
        argument = ArgumentSpec("path")
        self.assertTrue(argument.required)
        self.assertEqual(argument.completion, CompletionSpec())

    def test_commandlet_decorators_build_spec(self):
        @commandlet(
            name="hello",
            description="say hello",
            usage="hello [name]",
            examples=("hello world",),
            emits=("hello.greeting",),
            capabilities=("framework.console.output",),
        )
        @option("timeout", "timeout seconds", default="5")
        @option("password", "password", secret=True)
        @option("uppercase", "uppercase output", default="false", choices=("true", "false"))
        @argument("suffix", "suffix", required=False)
        @argument("name", "name to greet", required=False, completion="plugin")
        class Hello:
            pass

        spec = getattr(Hello, "spec")
        self.assertEqual(spec.name, "hello")
        self.assertEqual(spec.arguments[0].name, "suffix")
        self.assertEqual(spec.arguments[1].name, "name")
        self.assertFalse(spec.arguments[1].required)
        self.assertEqual(spec.arguments[1].completion, CompletionSpec("plugin"))
        self.assertEqual(spec.options[0].name, "timeout")
        self.assertEqual(spec.options[1].name, "password")
        self.assertTrue(spec.options[1].secret)
        self.assertEqual(spec.options[2].name, "uppercase")
        self.assertEqual(spec.options[2].choices, ("true", "false"))
        self.assertEqual(spec.emits, ("hello.greeting",))
        self.assertEqual(spec.capabilities, ("framework.console.output",))

    def test_command_context_metadata_default(self):
        context = CommandContext(db=None, source="test")
        self.assertEqual(context.metadata, {})

    def test_command_context_exposes_scoped_vars(self):
        context = CommandContext(db=None, source="test")
        context.vars.set("value", "abc")
        self.assertEqual(context.vars.get("value"), "abc")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other/value")
        with self.assertRaisesRegex(ValueError, "unqualified"):
            context.vars.get("other.value")

    def test_command_context_does_not_expose_raw_varstore(self):
        store = VarStore()
        store.set("other.secret", "hidden")
        context = CommandContext(db=None, source="test", _varstore=store)
        self.assertFalse(hasattr(context, "_varstore"))
        self.assertFalse(hasattr(context.vars, "store"))
        self.assertIsNone(context.vars.get("secret"))

    def test_command_context_vars_prefer_run_snapshot(self):
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
                    "capabilities": ("process.run",),
                },
            )
            result = context.process.run([sys.executable, "-c", "print('hello')"])
            requests = db.events_for_topic("framework.process.run.requested")
            results = db.events_for_topic("process.run")
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "hello\n")
        self.assertEqual(requests[0].payload["argv"], [sys.executable, "-c", "print('hello')"])
        self.assertEqual(results[0].payload["returncode"], 0)
        self.assertEqual(results[0].payload["request_event_id"], requests[0].id)

    def test_command_context_process_run_audits_missing_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="test")
            context.process.run([sys.executable, "-c", "print('hello')"])
            missing = db.events_for_topic("plugin.capability.missing")
        self.assertEqual(missing[0].payload["capability"], "process.run")

    def test_command_context_process_run_redacts_secret_argv(self):
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
                    "capabilities": ("framework.secret.resolve", "process.run"),
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
                    "capabilities": ("framework.secret.resolve", "process.run"),
                },
            )
            password = context.secrets.resolve(secret_ref.ref)
            context.process.run([sys.executable, "-c", "print('ok')"], env={"TOOL_PASSWORD": password or ""})
            request = db.events_for_topic("framework.process.run.requested")[0]
        self.assertNotIn("supersecret", str(request.payload))
        self.assertEqual(request.payload["env"]["TOOL_PASSWORD"], "[REDACTED]")
        self.assertEqual(request.payload["secrets"][0]["env"], "TOOL_PASSWORD")
        self.assertEqual(request.payload["secrets"][0]["name"], "test.password")

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
                metadata={"capabilities": ("process.run",)},
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
        self.assertEqual([chunk.stream for chunk in chunks], ["stdout", "stderr"])
        self.assertEqual(started[0].payload["argv"][0], sys.executable)
        self.assertEqual(stdout[0].payload["text"], "out\n")
        self.assertEqual(stderr[0].payload["text"], "err\n")
        self.assertEqual(exited[0].payload["returncode"], 0)

    def test_normalize_argv_rejects_shell_string(self):
        with self.assertRaisesRegex(TypeError, "sequence of strings"):
            normalize_argv("echo hello")

    def test_normalize_argv_rejects_empty_argv(self):
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            normalize_argv([])

    def test_format_table_aligns_mapping_rows(self):
        lines = format_table([{"name": "one", "value": 1}], ("name", "value"))
        self.assertEqual(lines, ["name  value", "----  -----", "one   1    "])

    def test_scoped_varstore_reads_only_its_namespace(self):
        store = VarStore()
        store.set("one.secret", "a")
        store.set("two.secret", "b")
        one = ScopedVarStore(store, "one")
        self.assertFalse(hasattr(one, "store"))
        self.assertFalse(hasattr(one, "run_values"))
        self.assertEqual(one.get("secret"), "a")
        self.assertNotEqual(one.get("secret"), "b")

    def test_scoped_varstore_reads_provider_scope_explicitly(self):
        store = VarStore()
        store.set("http/repo_exposure.proxy", "http://127.0.0.1:8080")
        store.set("global.proxy", "global-proxy")
        context = CommandContext(
            db=None,
            source="git_expose_check",
            _varstore=store,
            metadata={
                "var_scope": "http/repo_exposure/git_expose_check",
                "provider_scope": "http/repo_exposure",
                "provider_variables": ("proxy",),
            },
        )
        self.assertIsNone(context.vars.get("proxy"))
        self.assertEqual(context.vars.get_provider("proxy"), "http://127.0.0.1:8080")
        self.assertEqual(context.vars.get_global("proxy"), "global-proxy")

    def test_scoped_varstore_rejects_undeclared_provider_variable(self):
        store = VarStore()
        store.set("http/repo_exposure.proxy", "http://127.0.0.1:8080")
        context = CommandContext(
            db=None,
            source="git_expose_check",
            _varstore=store,
            metadata={
                "var_scope": "http/repo_exposure/git_expose_check",
                "provider_scope": "http/repo_exposure",
            },
        )
        with self.assertRaisesRegex(PermissionError, "provider variable not declared"):
            context.vars.get_provider("proxy")

    def test_effective_run_vars_include_immediate_provider_only(self):
        store = VarStore()
        store.set("cloud/aws.region", "us-east-1")
        store.set("cloud/aws/s3.bucket-list", "common.txt")
        store.set("cloud/aws/s3/public_bucket.proxy", "http://127.0.0.1:8080")
        store.set("cloud/aws/s3/public_bucket/check.timeout", "5")
        store.set("cloud/other.value", "ignored")
        snapshot = effective_run_vars(store, "cloud/aws/s3/public_bucket/check")
        self.assertEqual(snapshot["cloud/aws/s3/public_bucket.proxy"], "http://127.0.0.1:8080")
        self.assertEqual(snapshot["cloud/aws/s3/public_bucket/check.timeout"], "5")
        self.assertNotIn("cloud/aws.region", snapshot)
        self.assertNotIn("cloud/aws/s3.bucket-list", snapshot)
        self.assertNotIn("cloud/other.value", snapshot)

    def test_varstore_items_sorted(self):
        store = VarStore()
        store.set("b", 2)
        store.set("a", 1)
        self.assertEqual(store.items(), [("a", "1"), ("b", "2")])

    def test_commandlet_base_var_default_uses_cli_variable_default_order(self):
        store = VarStore()
        store.set("example.timeout", "7")
        context = CommandContext(None, source="example", _varstore=store)

        class Example(CommandletBase):
            spec = CommandSpec("example", "example")

        commandlet = Example()
        parser = commandlet.parser()
        parser.add_argument("--timeout", type=int, default=commandlet.var_default(context, "timeout", 3, cast=int))
        self.assertEqual(parser.parse_args([]).timeout, 7)
        self.assertEqual(parser.parse_args(["--timeout", "2"]).timeout, 2)

    def test_commandlet_base_values_or_var(self):
        store = VarStore()
        store.set("example.targets", "127.0.0.1, 127.0.0.2")
        context = CommandContext(None, source="example", _varstore=store)

        class Example(CommandletBase):
            spec = CommandSpec("example", "example")

        commandlet = Example()
        self.assertEqual(
            commandlet.values_or_var(context, [], "targets", required=True),
            ["127.0.0.1", "127.0.0.2"],
        )
        self.assertEqual(commandlet.values_or_var(context, ["198.51.100.1"], "targets"), ["198.51.100.1"])

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


if __name__ == "__main__":
    unittest.main()
