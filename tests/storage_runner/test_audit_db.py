# ruff: noqa: F403,F405
"""Storage runner tests split by responsibility."""

from tests.storage_runner.support import *  # noqa: F403,F405

class StorageRunnerAuditDbTests(unittest.TestCase):
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
            self.assertRegex(text, r"events=\d+")
            capabilities = {
                event.payload["capability"]
                for event in runner.db.events_for_topic("plugin.capability.used")
            }
            self.assertNotIn("db.manage", capabilities)
            self.assertIn("db.raw", capabilities)
            argument_events = runner.db.events_for_topic("command.run.arguments")
            self.assertEqual(argument_events[-1].payload["database_actions"], ["view"])

    def test_audit_show_prints_matching_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic")
                process_framework_requests(runner, ShellState())
            self.assertIn('"topic": "topic"', output.getvalue())
            self.assertIn('"value": 1', output.getvalue())

    def test_audit_list_capabilities_prints_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "plugin.capability.used",
                {"commandlet": "hostscanner", "capability": "network.connect", "declared": True},
                "hostscanner",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list capabilities plugin=hostscanner")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("Capability", text)
            self.assertIn("Code", text)
            self.assertIn("network.connect", text)
            self.assertIn("C401", text)
            self.assertIn("hostscanner", text)
            self.assertIn("observed", text)

    def test_audit_list_capabilities_prints_topic_subcode(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            event = runner.db.publish(
                "plugin.capability.used",
                {"commandlet": "fixture", "capability": "db.write:host.found", "declared": True},
                "fixture",
            )
            row = capability_inventory_row("db.write:host.found", {}, {"db.write:host.found": [event]}, {})

            self.assertEqual(row["Capability"], "db.write:host.found")
            self.assertEqual(row["Code"], "C102.224929")

    def test_audit_list_policy_prints_policy_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "policy.evaluated",
                {
                    "commandlet": "hostscanner",
                    "decision": "warn",
                    "warnings": ["198.51.100.10 is outside allowed network scope"],
                    "before": {"targets": ["192.0.2.10", "198.51.100.10"]},
                    "after": {"targets": ["192.0.2.10"]},
                    "job_id": None,
                    "pipeline_id": None,
                    "command_run_id": "step-1",
                },
                "framework",
                command_run_id="step-1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list policy decision=warn target=198.51.100.10")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("Decision", text)
            self.assertIn("Commandlet", text)
            self.assertIn("hostscanner", text)
            self.assertIn("warn", text)
            self.assertIn("198.51.100.10", text)
            self.assertIn("outside allowed network scope", text)

    def test_audit_list_policy_selects_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "policy.evaluated",
                {"commandlet": "hostscanner", "decision": "warn", "before": {"targets": ["198.51.100.10"]}, "after": {"targets": []}},
                "framework",
            )
            runner.db.publish(
                "policy.evaluated",
                {"commandlet": "http_probe", "decision": "warn", "before": {"targets": ["203.0.113.5"]}, "after": {"targets": []}},
                "framework",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list policy plugin=http_probe")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("http_probe", text)
            self.assertIn("203.0.113.5", text)
            self.assertNotIn("hostscanner", text)

    def test_audit_list_policy_reports_no_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list policy")
                process_framework_requests(runner, ShellState())
            self.assertIn("No policy decisions matched.", output.getvalue())

    def test_audit_list_topics_prints_topic_policy_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish(
                "plugin.topic.policy",
                {
                    "commandlet": "webfin",
                    "topic": "web.fingerprint",
                    "reason": "unregistered",
                    "decision": "audit",
                    "message": "webfin published topic without a registered schema: web.fingerprint",
                    "job_id": None,
                    "pipeline_id": None,
                    "command_run_id": "step-1",
                },
                "webfin",
                command_run_id="step-1",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list topics decision=audit reason=unregistered topic=web.fingerprint")
                process_framework_requests(runner, ShellState())
            text = output.getvalue()
            self.assertIn("Decision", text)
            self.assertIn("Reason", text)
            self.assertIn("webfin", text)
            self.assertIn("web.fingerprint", text)
            self.assertIn("unregistered", text)

    def test_audit_list_topics_reports_no_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit list topics")
                process_framework_requests(runner, ShellState())
            self.assertIn("No topic policy decisions matched.", output.getvalue())

    def test_audit_show_filters_since_until_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            first = runner.db.publish("topic", {"value": "old"}, "test")
            second = runner.db.publish("topic", {"value": "new"}, "test")
            with runner.db.connect() as conn:
                conn.execute("UPDATE events SET created_at = ? WHERE id = ?", ("2026-05-16T10:00:00+00:00", first.id))
                conn.execute("UPDATE events SET created_at = ? WHERE id = ?", ("2026-05-17T10:00:00+00:00", second.id))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic since=20260517 until=20260517")
                process_framework_requests(runner, ShellState())
            self.assertNotIn('"value": "old"', output.getvalue())
            self.assertIn('"value": "new"', output.getvalue())

    def test_audit_show_filters_since_step_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": "old"}, "test", command_run_id="old-run")
            runner.db.publish("topic", {"value": "new"}, "test", command_run_id="new-run")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("audit show topic=topic since=step:new-run")
                process_framework_requests(runner, ShellState())
            self.assertNotIn('"value": "old"', output.getvalue())
            self.assertIn('"value": "new"', output.getvalue())

    def test_audit_export_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.jsonl")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path} topic=topic")
                process_framework_requests(runner, ShellState())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(records[0]["topic"], "topic")
            self.assertEqual(records[0]["payload"]["value"], 1)

    def test_audit_export_writes_sqlite_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.sqlite3")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path}")
                process_framework_requests(runner, ShellState())
            self.assertEqual(EventStore(path).events_for_topic("topic")[0].payload["value"], 1)

    def test_audit_export_writes_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.pdf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"audit export file={path}")
                process_framework_requests(runner, ShellState())
            self.assertTrue(path.read_bytes().startswith(b"%PDF-1.4"))

    def test_audit_export_encrypted_pdf_requires_qpdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "audit.pdf")
            runner = make_runner(Path(tmp, "db.sqlite3"))
            with (
                patch("bywaf.plugins.runtime.audit.shutil.which", return_value=None),
                patch.dict("sys.modules", {"pikepdf": None}),
            ):
                with self.assertRaisesRegex(ValueError, "qpdf"):
                    runner.execute(f"audit export --encrypt file={path}")

    def test_db_new_file_creates_and_switches_active_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            runner.db.publish("topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertGreaterEqual(runner.db.table_counts()["events"], 2)
            self.assertEqual(runner.db.events_for_topic("framework.console.output.requested")[0].source, "db")
            self.assertEqual(EventStore(first).events_for_topic("topic")[0].payload["value"], 1)

    def test_db_new_refuses_existing_file_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with self.assertRaisesRegex(ValueError, "already exists"):
                runner.execute(f"db new file={second}")
            self.assertEqual(runner.db.path, first)
            self.assertEqual(EventStore(second).table_counts()["events"], 1)

    def test_db_new_rejects_value_carrying_file_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            runner = make_runner(first)
            with self.assertRaisesRegex(ValueError, "file=path"):
                runner.execute(f"db new --file={second}")
            self.assertEqual(runner.db.path, first)

    def test_db_new_force_backs_up_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp, "first.sqlite3")
            second = Path(tmp, "second.sqlite3")
            EventStore(second).publish("topic", {"value": 1}, "test")
            runner = make_runner(first)
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"db new --force file={second}")
            self.assertEqual(runner.db.path, second)
            self.assertGreaterEqual(runner.db.table_counts()["events"], 2)
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

    def test_db_stats_reports_main_and_artifact_database_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp, "db.sqlite3")
            runner = make_runner(db_path)
            source = Path(tmp, "proof.txt")
            source.write_text("proof", encoding="utf-8")
            runner.db.publish("custom.topic", {"value": 1}, "test")
            with contextlib.redirect_stdout(io.StringIO()):
                runner.execute(f"artifact attach step=run-1 file={source} name=proof.txt")
                process_framework_requests(runner, ShellState())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("db stats")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Database statistics", text)
            self.assertIn("Main database files", text)
            self.assertIn("Main database tables", text)
            self.assertIn("Events by topic", text)
            self.assertIn("custom.topic", text)
            self.assertIn("Artifacts", text)
            self.assertIn("artifacts: 1", text)
            self.assertIn("text/plain", text)
            argument_events = runner.db.events_for_topic("command.run.arguments")
            self.assertEqual(argument_events[-1].payload["database_actions"], ["view"])

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
                    runner.execute(f"db new --encrypt file={second}")
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
                    runner.execute(f"db new file={second}")
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
