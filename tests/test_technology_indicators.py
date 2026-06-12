"""Tests for passive technology/version indicator findings.

Coverage focus: technology indicators regression behavior.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from bywaf.app import make_runner
from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.technology_indicators import findings_from_event, tech_review, technology_indicators


class TechnologyIndicatorsTests(unittest.TestCase):
    """Groups regression coverage for passive technology/version indicator findings."""
    def test_apache_httpd_249_server_header_becomes_version_indicator(self):
        """Protect apache httpd 249 server header becomes version indicator behavior from regressions."""
        event = Event.new(
            "http.endpoint",
            {
                "url": "https://example.test/",
                "host": "example.test",
                "port": 443,
                "scheme": "https",
                "server": "Apache/2.4.49 (Unix)",
            },
            "test",
        )

        findings = findings_from_event(event)
        finding = cast(dict[str, Any], findings[0])

        self.assertEqual(finding["class"], "technology.version.apache_httpd_2_4_49_indicator")
        self.assertEqual(finding["confidence"], "medium")
        self.assertEqual(finding["confidence_basis"], "version_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2021-41773"]})
        self.assertEqual(finding["finding_scope"], "web_origin")
        self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
        self.assertIn("passive http.endpoint evidence", finding["evidence"])

    def test_apache_httpd_250_banner_becomes_service_indicator(self):
        """Protect apache httpd 250 banner becomes service indicator behavior from regressions."""
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.10", "port": 80, "protocol": "tcp", "banner": "Server: Apache/2.4.50"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.apache_httpd_2_4_50_indicator")
        self.assertEqual(finding["confidence_basis"], "version_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2021-42013"]})
        self.assertEqual(finding["finding_scope"], "service")
        self.assertEqual(finding["target_scope"], {"kind": "service", "value": "192.0.2.10:80/tcp"})

    def test_web_fingerprint_match_uses_fingerprint_basis(self):
        """Protect web fingerprint match uses fingerprint basis behavior from regressions."""
        event = Event.new(
            "web.fingerprint",
            {
                "url": "http://example.test/",
                "host": "example.test",
                "port": 80,
                "scheme": "http",
                "server": "Apache/2.4.49",
                "technologies": ["apache"],
            },
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["confidence_basis"], "fingerprint_indicator")

    def test_unlisted_apache_version_is_not_promoted(self):
        """Protect unlisted apache version is not promoted behavior from regressions."""
        event = Event.new(
            "http.endpoint",
            {"host": "example.test", "port": 443, "scheme": "https", "server": "Apache/2.4.58"},
            "test",
        )

        self.assertEqual(findings_from_event(event), [])

    def test_nginx_140_server_header_becomes_version_indicator(self):
        event = Event.new(
            "http.endpoint",
            {"host": "example.test", "port": 80, "scheme": "http", "server": "nginx/1.4.0"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.nginx_1_3_9_to_1_4_0_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2013-2028"]})
        self.assertEqual(finding["confidence_basis"], "version_indicator")

    def test_nginx_unlisted_version_is_not_promoted(self):
        event = Event.new(
            "http.endpoint",
            {"host": "example.test", "port": 80, "scheme": "http", "server": "nginx/1.4.1"},
            "test",
        )

        self.assertEqual(findings_from_event(event), [])

    def test_iis_60_server_header_becomes_version_indicator(self):
        event = Event.new(
            "http.endpoint",
            {"host": "legacy.example.test", "port": 80, "scheme": "http", "server": "Microsoft-IIS/6.0"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.microsoft_iis_6_0_indicator")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2017-7269"]})

    def test_openssl_101f_banner_becomes_version_indicator(self):
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "banner": "OpenSSL/1.0.1f"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.openssl_1_0_1_to_1_0_1f_indicator")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2014-0160"]})
        self.assertEqual(finding["target_scope"], {"kind": "service", "value": "192.0.2.10:443/tcp"})

    def test_openssl_fixed_version_is_not_promoted(self):
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "banner": "OpenSSL/1.0.1g"},
            "test",
        )

        self.assertEqual(findings_from_event(event), [])

    def test_vsftpd_234_banner_becomes_backdoor_indicator(self):
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.21", "port": 21, "protocol": "tcp", "banner": "220 (vsFTPd 2.3.4)"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.vsftpd_2_3_4_indicator")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2011-2523"]})
        self.assertEqual(finding["target_scope"], {"kind": "service", "value": "192.0.2.21:21/tcp"})

    def test_unrealircd_3281_banner_becomes_backdoor_indicator(self):
        event = Event.new(
            "tcp.banner",
            {"host": "192.0.2.66", "port": 6667, "protocol": "tcp", "banner": ":irc.example.test 004 user UnrealIRCd-3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp"},
            "test",
        )

        finding = cast(dict[str, Any], findings_from_event(event)[0])

        self.assertEqual(finding["class"], "technology.version.unrealircd_3_2_8_1_indicator")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["identifiers"], {"cve": ["CVE-2010-2075"]})

    def test_commandlet_dedupes_same_class_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="technology_indicators",
                metadata={"capabilities": ("db.write:finding.candidate", "framework.console.alert")},
            )
            events = [
                Event.new("http.endpoint", {"host": "example.test", "port": 80, "scheme": "http", "server": "Apache/2.4.49"}, "test"),
                Event.new("web.fingerprint", {"host": "example.test", "port": 80, "scheme": "http", "server": "Apache/2.4.49"}, "test"),
            ]

            list(technology_indicators.run(context, ["silent=true"], events))

            self.assertEqual(len(db.events_for_topic("finding.candidate")), 1)

    def test_tech_review_promotes_and_dedupes_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="tech_review",
                metadata={"capabilities": tech_review.spec.capabilities},
            )
            event = Event.new(
                "web.fingerprint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "Apache/2.4.49",
                    "technologies": ["apache"],
                },
                "test",
            )

            list(tech_review.run(context, ["silent=true"], [event]))

            candidates = db.events_for_topic("finding.candidate")
            deduped = db.events_for_topic("finding.new")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(len(deduped), 1)
            self.assertEqual(deduped[0].payload["class"], "technology.version.apache_httpd_2_4_49_indicator")
            self.assertEqual(deduped[0].payload["identifiers"], {"cve": ["CVE-2021-41773"]})
            self.assertEqual(deduped[0].payload["confidence_basis"], "fingerprint_indicator")
            self.assertEqual(deduped[0].payload["target_scope"], {"kind": "web_origin", "value": "https://example.test"})

    def test_webfin_tech_review_report_chain_groups_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            endpoint = runner.db.publish(
                "http.endpoint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "Apache/2.4.49",
                    "headers": {"Server": "Apache/2.4.49"},
                    "status": 200,
                },
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )
            runner.execute(f"webfin --from pipeline={endpoint.pipeline_id} topic=http.endpoint | tech_review | report status=all")

            candidates = runner.db.events_for_topic("finding.candidate")
            deduped = runner.db.events_for_topic("finding.new")
            rendered = runner.db.events_for_topic("report.rendered")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(len(deduped), 1)
            self.assertEqual(deduped[0].payload["identifiers"], {"cve": ["CVE-2021-41773"]})
            self.assertEqual(deduped[0].payload["confidence_basis"], "fingerprint_indicator")
            self.assertEqual(deduped[0].payload["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(rendered[0].payload["rows"], 1)

    def test_webfin_report_runs_passive_technology_synthesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            endpoint = runner.db.publish(
                "http.endpoint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "Apache/2.4.49",
                    "headers": {"Server": "Apache/2.4.49"},
                    "status": 200,
                },
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            runner.execute(f"webfin --from pipeline={endpoint.pipeline_id} topic=http.endpoint | report status=all")

            candidates = runner.db.events_for_topic("finding.candidate")
            deduped = runner.db.events_for_topic("finding.new")
            rendered = runner.db.events_for_topic("report.rendered")
            self.assertEqual(len(candidates), 1)
            self.assertEqual(len(deduped), 1)
            self.assertEqual(deduped[0].payload["class"], "technology.version.apache_httpd_2_4_49_indicator")
            self.assertEqual(deduped[0].payload["identifiers"], {"cve": ["CVE-2021-41773"]})
            self.assertEqual(rendered[0].payload["rows"], 1)

    def test_report_analyze_off_does_not_run_passive_technology_synthesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            endpoint = runner.db.publish(
                "http.endpoint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "Apache/2.4.49",
                    "headers": {"Server": "Apache/2.4.49"},
                    "status": 200,
                },
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            runner.execute(f"webfin --from pipeline={endpoint.pipeline_id} topic=http.endpoint | report status=all analyze=off")

            self.assertEqual(runner.db.events_for_topic("finding.candidate"), [])
            self.assertEqual(runner.db.events_for_topic("finding.new"), [])
            self.assertEqual(runner.db.events_for_topic("report.rendered")[0].payload["rows"], 0)

    def test_report_passive_synthesis_reuses_existing_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "http.endpoint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "Apache/2.4.49",
                    "headers": {"Server": "Apache/2.4.49"},
                    "status": 200,
                },
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            runner.execute("report pipeline=pipeline-a status=all")
            runner.execute("report pipeline=pipeline-a status=all")

            self.assertEqual(len(runner.db.events_for_topic("finding.candidate")), 1)
            self.assertEqual(len(runner.db.events_for_topic("finding.new")), 1)
            rendered = runner.db.events_for_topic("report.rendered")
            self.assertEqual(rendered[0].payload["rows"], 1)
            self.assertEqual(rendered[1].payload["rows"], 1)

    def test_webfin_report_synthesizes_nginx_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            endpoint = runner.db.publish(
                "http.endpoint",
                {
                    "url": "https://example.test/",
                    "host": "example.test",
                    "port": 443,
                    "scheme": "https",
                    "server": "nginx/1.4.0",
                    "headers": {"Server": "nginx/1.4.0"},
                    "status": 200,
                },
                "http_probe",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            runner.execute(f"webfin --from pipeline={endpoint.pipeline_id} topic=http.endpoint | report status=all")

            deduped = runner.db.events_for_topic("finding.new")
            self.assertEqual(len(deduped), 1)
            self.assertEqual(deduped[0].payload["class"], "technology.version.nginx_1_3_9_to_1_4_0_indicator")
            self.assertEqual(deduped[0].payload["identifiers"], {"cve": ["CVE-2013-2028"]})

    def test_report_synthesizes_vsftpd_banner_indicator(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "tcp.banner",
                {"host": "192.0.2.21", "port": 21, "protocol": "tcp", "banner": "220 (vsFTPd 2.3.4)"},
                "tcp_banner",
                pipeline_id="pipeline-a",
                command_run_id="run-a",
            )

            runner.execute("report pipeline=pipeline-a status=all")

            deduped = runner.db.events_for_topic("finding.new")
            self.assertEqual(len(deduped), 1)
            self.assertEqual(deduped[0].payload["class"], "technology.version.vsftpd_2_3_4_indicator")
            self.assertEqual(deduped[0].payload["identifiers"], {"cve": ["CVE-2011-2523"]})


if __name__ == "__main__":
    unittest.main()
