# ruff: noqa: F403,F405
"""Report command tests split by responsibility.

Coverage focus: report review regression behavior.
"""

from tests.report.support import *  # noqa: F403,F405


class ReportReviewTests(unittest.TestCase):
    """Finding review workflow tests for report and finding command aliases.

    The suite seeds candidate/new finding events and then verifies review
    decisions, filtering, ordering, and audit payloads through public commands.
    """

    def test_report_confirm_marks_selected_finding_confirmed(self):
        """Protect report confirm marks selected finding confirmed behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Manually validated issue",
                    "target": {"host": "web-1.test"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report confirm 1 pipeline=pipeline-a note=validated manually")
                process_framework_requests(runner, ShellState())

            # Confirmation is both visible feedback and durable
            # finding.reviewed state used by later report filters.
            self.assertIn("confirmed 1 finding", output.getvalue())
            review = runner.db.events_for_topic("finding.reviewed")[0]
            self.assertEqual(review.payload["finding_id"], "finding-1")
            self.assertEqual(review.payload["decision"], "confirmed")
            self.assertEqual(review.payload["note"], "validated manually")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=confirmed")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Confirmed findings:", text)
            self.assertIn("Manually validated issue", text)

    def test_finding_confirm_and_unconfirm_use_report_rows(self):
        """Protect finding confirm and unconfirm use report rows behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "finding_id": "finding-1",
                    "title": "Operator tracked issue",
                    "target": {"host": "web-1.test"},
                    "severity": "high",
                },
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                # `finding` is a review-oriented facade over the same report
                # row selection logic, so confirm/unconfirm should target the
                # exact row that report would display.
                runner.execute("finding confirm 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())
                runner.execute("finding unconfirm 1 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("confirmed 1 finding", output.getvalue())
            self.assertIn("unconfirmed 1 finding", output.getvalue())
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(
                [(event.payload["finding_id"], event.payload["decision"], event.payload["source"]) for event in reviews],
                [("finding-1", "confirmed", "finding"), ("finding-1", "unreviewed", "finding")],
            )

    def test_report_hides_reviewed_findings(self):
        """Protect report hides reviewed findings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.record_command_run_vars(
                job_id=None,
                pipeline_id="pipeline-a",
                command_run_id="run-a",
                commandlet="scanner",
                values={},
            )
            runner.db.publish("command.run.completed", {}, "scanner", pipeline_id="pipeline-a", command_run_id="run-a")
            runner.db.publish(
                "finding.new",
                {"finding_id": "finding-1", "title": "Reviewed finding", "target": {"host": "example.test"}},
                "finding_dedupe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.db.publish("finding.reviewed", {"finding_id": "finding-1"}, "report")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report")
                process_framework_requests(runner, ShellState())

            self.assertIn("no open findings", output.getvalue())

    def test_report_summarizes_review_state_and_shows_unreviewed_by_default(self):
        """Protect report summarizes review state and shows unreviewed by default behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            # Seed three findings and review two of them so the default open
            # report can prove both summary counts and hidden reviewed rows.
            for index, title in enumerate(("Accepted finding", "Deferred finding", "Open finding"), start=1):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": title,
                        "target": {"host": f"host-{index}.test"},
                        "severity": "medium",
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-2", "decision": "deferred"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Findings: 3 total", text)
            self.assertIn("Review: 1 accepted, 0 confirmed, 1 deferred, 0 rejected, 1 unreviewed", text)
            self.assertIn("Open findings:", text)
            self.assertIn("Open finding", text)
            self.assertNotIn("Accepted finding", text)
            self.assertNotIn("Deferred finding", text)
            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(
                rendered.payload["counts"],
                {"total": 3, "accepted": 1, "confirmed": 0, "deferred": 1, "rejected": 0, "unreviewed": 1},
            )
            self.assertEqual(rendered.payload["groups"], ["finding-3"])

    def test_report_status_all_shows_reviewed_and_unreviewed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Accepted finding", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-2", "title": "Open finding", "target": {"host": "b.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("All findings:", text)
            self.assertIn("Accepted finding", text)
            self.assertIn("Open finding", text)

    def test_report_accepted_first_orders_reviewed_findings_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            # The insertion order puts the open finding first. The report flag
            # should promote accepted reviewed findings without changing their
            # underlying event history.
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Open finding", "target": {"host": "b.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-2", "title": "Accepted finding", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-2", "decision": "accepted"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all --accepted-first")
                process_framework_requests(runner, ShellState())

            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["order"], "accepted-first")
            self.assertEqual(rendered.payload["groups"], ["finding-2", "finding-1"])
            self.assertLess(output.getvalue().index("Accepted finding"), output.getvalue().index("Open finding"))

    def test_report_candidates_first_orders_candidate_findings_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.confirmed",
                {"finding_id": "finding-1", "title": "Confirmed finding", "target": {"host": "a.test"}, "status": "confirmed"},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-2", "title": "Candidate finding", "target": {"host": "b.test"}, "status": "potential"},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all --candidates-first")
                process_framework_requests(runner, ShellState())

            rendered = runner.db.events_for_topic("report.rendered")[0]
            self.assertEqual(rendered.payload["order"], "candidates-first")
            self.assertEqual(rendered.payload["groups"], ["finding-2", "finding-1"])
            self.assertIn("Candidate finding", output.getvalue())
            self.assertIn("Confirmed finding", output.getvalue())

    def test_report_accepts_selection_ranges_and_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index in range(1, 6):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": f"Finding {index}",
                        "target": {"host": f"host-{index}.test"},
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report accept 1-2,4 pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("accepted 3 findings", output.getvalue())
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(
                [(event.payload["finding_id"], event.payload["decision"]) for event in reviews],
                [("finding-1", "accepted"), ("finding-2", "accepted"), ("finding-4", "accepted")],
            )
            capabilities = runner.db.events_for_topic("plugin.capability.used")
            self.assertTrue(any(event.payload.get("capability") == "finding.review" for event in capabilities))

    def test_report_accept_all_marks_visible_unreviewed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index in range(1, 4):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"finding-{index}",
                        "title": f"Finding {index}",
                        "target": {"host": f"host-{index}.test"},
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report accept all pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            self.assertIn("accepted 3 findings", output.getvalue())
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual(len(reviews), 3)
            self.assertTrue(all(event.payload["decision"] == "accepted" for event in reviews))

    def test_report_defer_records_note_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Needs review", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report defer 1 pipeline=pipeline-a note=needs manual validation")
                process_framework_requests(runner, ShellState())

            self.assertIn("deferred 1 finding", output.getvalue())
            review = runner.db.events_for_topic("finding.reviewed")[0]
            self.assertEqual(review.payload["finding_id"], "finding-1")
            self.assertEqual(review.payload["decision"], "deferred")
            self.assertEqual(review.payload["note"], "needs manual validation")

    def test_report_accept_defer_reject_flow_uses_deduped_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            for index, (title, host) in enumerate(
                (
                    ("Accepted issue", "accepted.test"),
                    ("Deferred issue", "deferred.test"),
                    ("Rejected issue", "rejected.test"),
                ),
                start=1,
            ):
                runner.db.publish(
                    "finding.candidate",
                    {
                        "finding_id": f"candidate-{index}",
                        "title": title,
                        "class": "web.exposure.git_config",
                        "target": {"scheme": "https", "host": host, "path": "/.git/config"},
                        "affected": [{"url": f"https://{host}/.git/config"}],
                        "identifiers": {"cwe": ["CWE-538"]},
                        "severity": "high",
                    },
                    "scanner",
                    pipeline_id="pipeline-a",
                    command_run_id="step-a",
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("finding_dedupe -s")
                process_framework_requests(runner, ShellState())
                runner.execute("report accept 1 pipeline=pipeline-a note=validated")
                process_framework_requests(runner, ShellState())
                runner.execute("report defer 1 pipeline=pipeline-a note=owner follow-up")
                process_framework_requests(runner, ShellState())
                runner.execute("report reject 1 pipeline=pipeline-a note=false positive")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("accepted 1 finding", text)
            self.assertIn("deferred 1 finding", text)
            self.assertIn("rejected 1 finding", text)
            reviews = runner.db.events_for_topic("finding.reviewed")
            self.assertEqual([event.payload["decision"] for event in reviews], ["accepted", "deferred", "rejected"])
            self.assertEqual([event.payload["note"] for event in reviews], ["validated", "owner follow-up", "false positive"])
            self.assertTrue(all(event.payload["source"] == "report" for event in reviews))
            self.assertEqual(len(runner.db.events_for_topic("finding.new")), 3)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a")
                process_framework_requests(runner, ShellState())

            open_text = output.getvalue()
            self.assertIn("Review: 1 accepted, 0 confirmed, 1 deferred, 1 rejected, 0 unreviewed", open_text)
            self.assertIn("no open findings", open_text)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=all")
                process_framework_requests(runner, ShellState())

            all_text = output.getvalue()
            self.assertIn("Accepted issue", all_text)
            self.assertIn("Deferred issue", all_text)
            self.assertIn("Rejected issue", all_text)

    def test_report_latest_review_decision_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {"finding_id": "finding-1", "title": "Flipped finding", "target": {"host": "a.test"}},
                "scanner",
                pipeline_id="pipeline-a",
                command_run_id="step-a",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "accepted"},
                "report",
            )
            runner.db.publish(
                "finding.reviewed",
                {"finding_id": "finding-1", "decision": "rejected"},
                "report",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                runner.execute("report pipeline=pipeline-a status=rejected")
                process_framework_requests(runner, ShellState())

            text = output.getvalue()
            self.assertIn("Findings: 1 total", text)
            self.assertIn("Review: 0 accepted, 0 confirmed, 0 deferred, 1 rejected, 0 unreviewed", text)
            self.assertIn("Rejected findings:", text)
            self.assertIn("Flipped finding", text)
