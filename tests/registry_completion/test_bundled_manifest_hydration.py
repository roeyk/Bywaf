# ruff: noqa: F403,F405
"""Bundled manifest hydration tests for lean Python commandlet specs.

Coverage focus: registry completion bundled manifest hydration regression behavior.
"""

from tests.registry_completion.support import *  # noqa: F403,F405


class BundledManifestHydrationTests(unittest.TestCase):
    """Groups regression coverage for bundled manifest hydration tests for lean Python commandlet specs."""
    def setUp(self):
        """Prepare shared fixtures for this test case."""
        self.registry = PluginRegistry.discover()

    def test_bundled_sidecar_hydrates_runtime_security_metadata(self):
        """Protect bundled sidecar hydrates runtime security metadata behavior from regressions."""
        from bywaf.plugins.analysis.finding import Finding
        from bywaf.plugins.analysis.finding.dedupe import FINDING_INPUT_TOPICS, FINDING_OUTPUT_TOPICS, FindingDedupe
        from bywaf.plugins.analysis.finding.report import REPORT_FINDING_TOPICS, FindingReport
        from bywaf.plugins.analysis.report import Report
        from bywaf.plugins.analysis.yara_scan import YaraScan
        from bywaf.plugins.discovery.hostscanner import HostScanner
        from bywaf.plugins.http.eyewitness import EyeWitness
        from bywaf.plugins.http.auth import HttpAuth
        from bywaf.plugins.http.headers import HttpHeaders
        from bywaf.plugins.http.methods import HttpMethods
        from bywaf.plugins.http.probe import HttpProbe
        from bywaf.plugins.http.nikto import Nikto
        from bywaf.plugins.http.repo_exposure import GitExposeCheck, RepoExposure
        from bywaf.plugins.http.screenshotter import Screenshotter
        from bywaf.plugins.http.webfin import WebFingerprint
        from bywaf.plugins.identity.ldap_probe import LdapProbe
        from bywaf.plugins.identity.smb_probe import SmbProbe
        from bywaf.plugins.network.snmp_get import SnmpGet
        from bywaf.plugins.network.portscanner import PortScanner
        from bywaf.plugins.network.portscanner.ports import Ports
        from bywaf.plugins.network.ssh_probe import SshProbe
        from bywaf.plugins.os.cat import Cat
        from bywaf.plugins.os.less import Less
        from bywaf.plugins.os.ls import Ls
        from bywaf.plugins.recon.shodan_lookup import ShodanLookup
        from bywaf.plugins.runtime.artifact import ArtifactCommand, SearchCommand
        from bywaf.plugins.runtime.audit import Audit
        from bywaf.plugins.runtime.bundle import BundleCommand
        from bywaf.plugins.runtime.control import Cancel, RuntimeSignal
        from bywaf.plugins.runtime.inventory import (
            HOST_TOPICS,
            SERVICE_TOPICS,
            WEB_TOPICS,
            Banners,
            Certs,
            Hosts,
            Paths,
            Routes,
            Screenshots,
            Services,
            Shares,
            Wafs,
            Web,
        )
        from bywaf.plugins.runtime.job import Job
        from bywaf.plugins.runtime.key import Key
        from bywaf.plugins.runtime.name import Name
        from bywaf.plugins.runtime.note import Note
        from bywaf.plugins.runtime.pipeline import Pipeline
        from bywaf.plugins.runtime.results import ResultAlias, Results
        from bywaf.plugins.runtime.schemas import Schemas
        from bywaf.plugins.runtime.step import Step
        from bywaf.plugins.runtime.watchdog import Watchdog
        from bywaf.plugins.storage.db import Db
        from bywaf.plugins.wireless.wifi_scan import WifiScan

        raw_classes = (
            ArtifactCommand,
            Audit,
            BundleCommand,
            Cancel,
            Cat,
            Db,
            EyeWitness,
            Finding,
            FindingDedupe,
            FindingReport,
            GitExposeCheck,
            HostScanner,
            HttpAuth,
            HttpHeaders,
            HttpMethods,
            HttpProbe,
            Job,
            Key,
            LdapProbe,
            Less,
            Ls,
            Name,
            Nikto,
            Note,
            Pipeline,
            Ports,
            PortScanner,
            RepoExposure,
            ResultAlias,
            Results,
            RuntimeSignal,
            Schemas,
            Screenshotter,
            SearchCommand,
            ShodanLookup,
            SmbProbe,
            SnmpGet,
            SshProbe,
            Step,
            Report,
            WebFingerprint,
            Watchdog,
            WifiScan,
            YaraScan,
        )
        for raw_class in raw_classes:
            with self.subTest(commandlet=raw_class.__name__):
                spec = raw_class().spec
                self.assertEqual(spec.capabilities, ())
                self.assertEqual(spec.database_actions, ())

        lean_catalog_classes = (
            Finding,
            FindingDedupe,
            FindingReport,
            GitExposeCheck,
            HostScanner,
            HttpHeaders,
            HttpProbe,
            LdapProbe,
            Ports,
            PortScanner,
            RepoExposure,
            Report,
            ShodanLookup,
            SmbProbe,
            SnmpGet,
            SshProbe,
            WebFingerprint,
            YaraScan,
        )
        for raw_class in lean_catalog_classes:
            with self.subTest(commandlet=f"{raw_class.__name__}-catalog"):
                spec = raw_class().spec
                self.assertEqual(spec.consumes, ())
                self.assertEqual(spec.emits, ())

        inventory_classes = (
            Banners,
            Certs,
            Hosts,
            Paths,
            Routes,
            Screenshots,
            Services,
            Shares,
            Wafs,
            Web,
        )
        for inventory_class in inventory_classes:
            with self.subTest(commandlet=inventory_class.__name__):
                spec = inventory_class().spec
                self.assertEqual(spec.capabilities, ())
                self.assertEqual(spec.consumes, ())
                self.assertEqual(spec.database_actions, ())

        self.assertIn("db.raw", self.registry.get("audit").spec.capabilities)
        self.assertIn("artifact.read", self.registry.get("artifact").spec.capabilities)
        self.assertEqual(self.registry.get("artifact").spec.database_actions, ("view", "write"))
        self.assertIn("artifact.read", self.registry.get("bundle").spec.capabilities)
        self.assertEqual(self.registry.get("bundle").spec.database_actions, ("view", "write"))
        self.assertIn("bundle.created", self.registry.get("bundle").spec.emits)
        self.assertIn("framework.job.control", self.registry.get("cancel").spec.capabilities)
        self.assertIn("filesystem.read", self.registry.get("cat").spec.capabilities)
        self.assertIn("db.manage", self.registry.get("db").spec.capabilities)
        self.assertEqual(self.registry.get("db").spec.database_actions, ("view", "manage"))
        self.assertIn("network.connect", self.registry.get("eyewitness").spec.capabilities)
        self.assertEqual(self.registry.get("eyewitness").spec.consumes, ("http.endpoint",))
        self.assertIn("finding.review", self.registry.get("finding").spec.capabilities)
        self.assertEqual(self.registry.get("finding").spec.consumes, REPORT_FINDING_TOPICS)
        self.assertEqual(self.registry.get("finding").spec.emits, ("finding.reviewed",))
        self.assertEqual(self.registry.get("finding").spec.database_actions, ("write",))
        self.assertIn("framework.console.output", self.registry.get("finding_dedupe").spec.capabilities)
        self.assertEqual(self.registry.get("finding_dedupe").spec.consumes, FINDING_INPUT_TOPICS)
        self.assertEqual(self.registry.get("finding_dedupe").spec.emits, FINDING_OUTPUT_TOPICS)
        self.assertIn("framework.render.table", self.registry.get("finding_report").spec.capabilities)
        self.assertEqual(
            self.registry.get("finding_report").spec.consumes,
            (
                "finding.candidate",
                "finding.confirmed",
                "finding.new",
                "finding.merge_candidate",
                "nikto.finding",
                "vulnerability.found",
                "vulnerability.potential",
                "vulnerability.confirmed",
                "vulnerability.speculative",
                "vulnerability.false_positive",
            ),
        )
        self.assertEqual(
            self.registry.get("finding_report").spec.emits,
            ("framework.render.table.requested", "artifact.attached"),
        )
        self.assertIn("network.connect", self.registry.get("git_expose_check").spec.capabilities)
        self.assertEqual(self.registry.get("git_expose_check").spec.consumes, ("http.endpoint",))
        self.assertEqual(
            self.registry.get("git_expose_check").spec.emits,
            ("repo.git_config.checked", "finding.candidate"),
        )
        self.assertIn("network.connect", self.registry.get("hostscanner").spec.capabilities)
        self.assertEqual(self.registry.get("hostscanner").spec.emits, ("host.found", "name.resolved", "tool.error"))
        self.assertIn("network.connect", self.registry.get("http_headers").spec.capabilities)
        self.assertEqual(self.registry.get("http_headers").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("http_headers").spec.emits, ("http.headers", "finding.candidate"))
        self.assertEqual(self.registry.get("http_headers").spec.database_actions, ("write",))
        self.assertIn("network.connect", self.registry.get("http_auth").spec.capabilities)
        self.assertEqual(self.registry.get("http_auth").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("http_auth").spec.emits, ("http.auth", "finding.candidate"))
        self.assertEqual(self.registry.get("http_auth").spec.database_actions, ("write",))
        self.assertIn("network.connect", self.registry.get("http_methods").spec.capabilities)
        self.assertEqual(self.registry.get("http_methods").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("http_methods").spec.emits, ("http.methods", "finding.candidate"))
        self.assertEqual(self.registry.get("http_methods").spec.database_actions, ("write",))
        self.assertIn("network.connect", self.registry.get("http_probe").spec.capabilities)
        self.assertEqual(self.registry.get("http_probe").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("http_probe").spec.emits, ("http.endpoint",))
        self.assertIn("framework.job.control", self.registry.get("job").spec.capabilities)
        self.assertEqual(self.registry.get("job").spec.database_actions, ("view", "write"))
        self.assertIn("db.write:key.generated", self.registry.get("key").spec.capabilities)
        self.assertIn("key.generated", self.registry.get("key").spec.emits)
        self.assertIn("network.connect", self.registry.get("ldap_probe").spec.capabilities)
        self.assertEqual(self.registry.get("ldap_probe").spec.emits, ("ldap.server",))
        self.assertIn("framework.file.page", self.registry.get("less").spec.capabilities)
        self.assertIn("filesystem.read", self.registry.get("ls").spec.capabilities)
        self.assertIn("framework.console.output", self.registry.get("name").spec.capabilities)
        self.assertIn("filesystem.write", self.registry.get("note").spec.capabilities)
        self.assertEqual(self.registry.get("note").spec.database_actions, ("view", "write"))
        self.assertIn("network.connect", self.registry.get("nikto").spec.capabilities)
        self.assertEqual(
            self.registry.get("management_exposure").spec.consumes,
            ("port.open", "service.detected", "http.endpoint", "web.fingerprint", "tcp.banner"),
        )
        self.assertEqual(self.registry.get("management_exposure").spec.emits, ("finding.candidate",))
        self.assertEqual(self.registry.get("nikto").spec.consumes, ("http.endpoint", "web.fingerprint"))
        self.assertIn("nikto.finding", self.registry.get("nikto").spec.emits)
        self.assertIn("framework.pipeline.control", self.registry.get("pipeline").spec.capabilities)
        self.assertEqual(self.registry.get("pipeline").spec.database_actions, ("view", "write"))
        self.assertIn("network.connect", self.registry.get("portscanner").spec.capabilities)
        self.assertEqual(self.registry.get("portscanner").spec.consumes, ("host.found", "network.route.hop"))
        self.assertEqual(
            self.registry.get("portscanner").spec.emits,
            ("port.open", "finding.candidate", "name.resolved", "tool.error"),
        )
        self.assertEqual(self.registry.get("ports").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("ports").spec.database_actions, ("view",))
        self.assertIn("network.connect", self.registry.get("repo_exposure").spec.capabilities)
        self.assertEqual(self.registry.get("repo_exposure").spec.consumes, ("http.endpoint",))
        self.assertEqual(
            self.registry.get("repo_exposure").spec.emits,
            ("repo.git_config.checked", "finding.candidate"),
        )
        self.assertIn("framework.file.page", self.registry.get("result").spec.capabilities)
        self.assertIn("framework.file.page", self.registry.get("report").spec.capabilities)
        self.assertEqual(
            self.registry.get("report").spec.consumes,
            (*REPORT_FINDING_TOPICS, "service.detected", "tcp.banner", "http.endpoint", "web.fingerprint"),
        )
        self.assertEqual(
            self.registry.get("report").spec.emits,
            (
                "finding.candidate",
                "finding.new",
                "finding.duplicate",
                "finding.updated",
                "finding.merge_candidate",
                "finding.reviewed",
                "report.scope.saved",
                "report.rendered",
            ),
        )
        self.assertEqual(self.registry.get("report").spec.database_actions, ("view", "write"))
        self.assertIn("db.write:finding.new", self.registry.get("report").spec.capabilities)
        self.assertEqual(self.registry.get("results").spec.database_actions, ("view",))
        self.assertIn("framework.pipeline.control", self.registry.get("signal").spec.capabilities)
        self.assertIn("framework.file.page", self.registry.get("schemas").spec.capabilities)
        self.assertEqual(self.registry.get("schemas").spec.database_actions, ("view",))
        self.assertIn("network.connect", self.registry.get("screenshotter").spec.capabilities)
        self.assertEqual(self.registry.get("screenshotter").spec.consumes, ("http.endpoint",))
        self.assertIn("artifact.read", self.registry.get("search").spec.capabilities)
        self.assertEqual(self.registry.get("search").spec.database_actions, ("view",))
        self.assertIn("network.connect", self.registry.get("shodan_lookup").spec.capabilities)
        self.assertEqual(self.registry.get("shodan_lookup").spec.emits, ("shodan.host", "shodan.result"))
        self.assertIn("network.connect", self.registry.get("smb_probe").spec.capabilities)
        self.assertEqual(self.registry.get("smb_probe").spec.emits, ("smb.server",))
        self.assertIn("network.connect", self.registry.get("snmp_get").spec.capabilities)
        self.assertEqual(self.registry.get("snmp_get").spec.emits, ("snmp.value",))
        self.assertIn("network.connect", self.registry.get("ssh_probe").spec.capabilities)
        self.assertEqual(self.registry.get("ssh_probe").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("ssh_probe").spec.emits, ("ssh.service",))
        self.assertEqual(
            self.registry.get("technology_indicators").spec.consumes,
            ("service.detected", "tcp.banner", "http.endpoint", "web.fingerprint"),
        )
        self.assertEqual(self.registry.get("technology_indicators").spec.emits, ("finding.candidate",))
        self.assertIn("db.write:finding.candidate", self.registry.get("technology_indicators").spec.capabilities)
        self.assertEqual(
            self.registry.get("tech_review").spec.consumes,
            ("service.detected", "tcp.banner", "http.endpoint", "web.fingerprint"),
        )
        self.assertEqual(
            self.registry.get("tech_review").spec.emits,
            ("finding.candidate", "finding.new", "finding.duplicate", "finding.updated", "finding.merge_candidate"),
        )
        self.assertIn("db.write:finding.new", self.registry.get("tech_review").spec.capabilities)
        self.assertIn("framework.console.output", self.registry.get("step").spec.capabilities)
        self.assertEqual(self.registry.get("step").spec.database_actions, ("view",))
        self.assertIn("network.connect", self.registry.get("webfin").spec.capabilities)
        self.assertEqual(self.registry.get("webfin").spec.consumes, ("http.endpoint",))
        self.assertEqual(self.registry.get("webfin").spec.emits, ("web.fingerprint",))
        self.assertEqual(self.registry.get("webfin").spec.database_actions, ("write",))
        self.assertIn("network.listen", self.registry.get("wifi_scan").spec.capabilities)
        self.assertEqual(self.registry.get("wifi_scan").spec.emits, ("wifi.network", "kismet.network"))
        self.assertIn("db.write:watchdog.timeout", self.registry.get("watchdog").spec.capabilities)
        self.assertIn("watchdog.timeout", self.registry.get("watchdog").spec.emits)
        self.assertIn("filesystem.read", self.registry.get("yara_scan").spec.capabilities)
        self.assertEqual(self.registry.get("yara_scan").spec.emits, ("yara.match",))

        inventory_names = (
            "banners",
            "certs",
            "hosts",
            "paths",
            "routes",
            "screenshots",
            "services",
            "shares",
            "wafs",
            "web",
        )
        for name in inventory_names:
            with self.subTest(commandlet=name):
                spec = self.registry.get(name).spec
                self.assertIn("framework.console.output", spec.capabilities)
                self.assertIn("framework.file.page", spec.capabilities)
                self.assertEqual(spec.database_actions, ("view",))
        self.assertEqual(self.registry.get("hosts").spec.consumes, HOST_TOPICS)
        self.assertEqual(self.registry.get("services").spec.consumes, SERVICE_TOPICS)
        self.assertEqual(self.registry.get("web").spec.consumes, WEB_TOPICS)
        self.assertEqual(self.registry.get("screenshots").spec.consumes, ("web.screenshotted_host",))
