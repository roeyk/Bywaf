# ruff: noqa: F403,F405
"""Bundled manifest hydration tests for lean Python commandlet specs."""

from tests.registry_completion.support import *  # noqa: F403,F405


class BundledManifestHydrationTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry.discover()

    def test_bundled_sidecar_hydrates_runtime_security_metadata(self):
        from bywaf.plugins.discovery.hostscanner import HostScanner
        from bywaf.plugins.http.eyewitness import EyeWitness
        from bywaf.plugins.http.http_probe import HttpProbe
        from bywaf.plugins.http.nikto import Nikto
        from bywaf.plugins.http.screenshotter import Screenshotter
        from bywaf.plugins.http.webfin import WebFingerprint
        from bywaf.plugins.network.portscanner import PortScanner
        from bywaf.plugins.network.portscanner.ports import Ports
        from bywaf.plugins.os.cat import Cat
        from bywaf.plugins.os.less import Less
        from bywaf.plugins.os.ls import Ls
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
            HostScanner,
            HttpProbe,
            Job,
            Key,
            Less,
            Ls,
            Name,
            Nikto,
            Note,
            Pipeline,
            Ports,
            PortScanner,
            ResultAlias,
            Results,
            RuntimeSignal,
            Schemas,
            Screenshotter,
            SearchCommand,
            Step,
            WebFingerprint,
            Watchdog,
            WifiScan,
        )
        for raw_class in raw_classes:
            with self.subTest(commandlet=raw_class.__name__):
                spec = raw_class().spec
                self.assertEqual(spec.capabilities, ())
                self.assertEqual(spec.database_actions, ())

        lean_catalog_classes = (
            HostScanner,
            HttpProbe,
            Ports,
            PortScanner,
            WebFingerprint,
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
        self.assertIn("network.connect", self.registry.get("hostscanner").spec.capabilities)
        self.assertEqual(self.registry.get("hostscanner").spec.emits, ("host.found", "name.resolved"))
        self.assertIn("network.connect", self.registry.get("http_probe").spec.capabilities)
        self.assertEqual(self.registry.get("http_probe").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("http_probe").spec.emits, ("http.endpoint",))
        self.assertIn("framework.job.control", self.registry.get("job").spec.capabilities)
        self.assertEqual(self.registry.get("job").spec.database_actions, ("view", "write"))
        self.assertIn("db.write:key.generated", self.registry.get("key").spec.capabilities)
        self.assertIn("key.generated", self.registry.get("key").spec.emits)
        self.assertIn("framework.file.page", self.registry.get("less").spec.capabilities)
        self.assertIn("filesystem.read", self.registry.get("ls").spec.capabilities)
        self.assertIn("framework.console.output", self.registry.get("name").spec.capabilities)
        self.assertIn("filesystem.write", self.registry.get("note").spec.capabilities)
        self.assertEqual(self.registry.get("note").spec.database_actions, ("view", "write"))
        self.assertIn("network.connect", self.registry.get("nikto").spec.capabilities)
        self.assertEqual(self.registry.get("nikto").spec.consumes, ("http.endpoint", "web.fingerprint"))
        self.assertIn("nikto.finding", self.registry.get("nikto").spec.emits)
        self.assertIn("framework.pipeline.control", self.registry.get("pipeline").spec.capabilities)
        self.assertEqual(self.registry.get("pipeline").spec.database_actions, ("view", "write"))
        self.assertIn("network.connect", self.registry.get("portscanner").spec.capabilities)
        self.assertEqual(self.registry.get("portscanner").spec.consumes, ("host.found", "network.route.hop"))
        self.assertEqual(self.registry.get("portscanner").spec.emits, ("port.open", "finding.candidate"))
        self.assertEqual(self.registry.get("ports").spec.consumes, ("port.open",))
        self.assertEqual(self.registry.get("ports").spec.database_actions, ("view",))
        self.assertIn("framework.file.page", self.registry.get("result").spec.capabilities)
        self.assertEqual(self.registry.get("results").spec.database_actions, ("view",))
        self.assertIn("framework.pipeline.control", self.registry.get("signal").spec.capabilities)
        self.assertIn("framework.file.page", self.registry.get("schemas").spec.capabilities)
        self.assertEqual(self.registry.get("schemas").spec.database_actions, ("view",))
        self.assertIn("network.connect", self.registry.get("screenshotter").spec.capabilities)
        self.assertEqual(self.registry.get("screenshotter").spec.consumes, ("http.endpoint",))
        self.assertIn("artifact.read", self.registry.get("search").spec.capabilities)
        self.assertEqual(self.registry.get("search").spec.database_actions, ("view",))
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
