# ruff: noqa: F403,F405
"""Registry and completion tests split by responsibility."""

from tests.registry_completion.support import *  # noqa: F403,F405
class RegistryBundledPluginTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry.discover()

    def test_discovers_bundled_plugins(self):
        self.assertIn("hostscanner", self.registry.names())
        self.assertIn("dns_lookup", self.registry.names())
        self.assertIn("ldap_probe", self.registry.names())
        self.assertIn("ports", self.registry.names())
        self.assertIn("portscanner", self.registry.names())
        self.assertIn("shodan_lookup", self.registry.names())
        self.assertIn("smb_probe", self.registry.names())
        self.assertIn("snmp_get", self.registry.names())
        self.assertIn("ssh_probe", self.registry.names())
        self.assertIn("traceroute", self.registry.names())
        self.assertIn("eyewitness", self.registry.names())
        self.assertIn("http_auth", self.registry.names())
        self.assertIn("http_headers", self.registry.names())
        self.assertIn("http_methods", self.registry.names())
        self.assertIn("http_probe", self.registry.names())
        self.assertIn("nikto", self.registry.names())
        self.assertIn("git_expose_check", self.registry.names())
        self.assertIn("repo_exposure", self.registry.names())
        self.assertIn("screenshotter", self.registry.names())
        self.assertIn("webfin", self.registry.names())
        self.assertIn("wifi_scan", self.registry.names())
        self.assertIn("finding_dedupe", self.registry.names())
        self.assertIn("finding_report", self.registry.names())
        self.assertIn("report", self.registry.names())
        self.assertIn("results", self.registry.names())
        self.assertIn("result", self.registry.names())
        self.assertIn("hosts", self.registry.names())
        self.assertIn("services", self.registry.names())
        self.assertIn("web", self.registry.names())
        self.assertIn("yara_scan", self.registry.names())
        self.assertIn("db", self.registry.names())
        self.assertIn("job", self.registry.names())
        self.assertIn("pipeline", self.registry.names())
        self.assertIn("end", self.registry.names())
        self.assertIn("kill", self.registry.names())
        self.assertIn("cancel", self.registry.names())
        self.assertIn("pause", self.registry.names())
        self.assertIn("resume", self.registry.names())
        self.assertIn("stop", self.registry.names())
        self.assertIn("signal", self.registry.names())
        self.assertIn("audit", self.registry.names())
        self.assertIn("bundle", self.registry.names())
        self.assertIn("key", self.registry.names())
        self.assertIn("note", self.registry.names())
        self.assertIn("name", self.registry.names())
        self.assertIn("artifact", self.registry.names())
        self.assertIn("watchdog", self.registry.names())

    def test_bundled_plugins_are_loaded_from_config_list(self):
        entries = parse_package_plugin_config("bywaf.plugins", "plugins.toml")
        self.assertEqual(
            entries,
            [
                "discovery.hostscanner",
                "analysis.finding",
                "analysis.finding_dedupe",
                "analysis.finding_report",
                "analysis.report",
                "analysis.technology_indicators",
                "analysis.yara_scan",
                "identity.ldap_probe",
                "identity.smb_probe",
                "network.management_exposure",
                "network.portscanner",
                "network.service_probe",
                "network.snmp_get",
                "network.ssh_probe",
                "network.tcp_banner",
                "network.traceroute",
                "recon.dns_lookup",
                "recon.dns_enum",
                "recon.shodan_lookup",
                "http.http_headers",
                "http.eyewitness",
                "http.http_auth",
                "http.http_cors",
                "http.http_methods",
                "http.http_paths",
                "http.http_probe",
                "http.nikto",
                "http.repo_exposure",
                "http.screenshotter",
                "http.tls_probe",
                "http.waf_detect",
                "http.webfin",
                "wireless.wifi_scan",
                "runtime.job",
                "runtime.pipeline",
                "runtime.step",
                "runtime.results",
                "runtime.inventory",
                "runtime.schemas",
                "runtime.control",
                "runtime.audit",
                "runtime.bundle",
                "runtime.key",
                "runtime.note",
                "runtime.name",
                "runtime.artifact",
                "runtime.watchdog",
                "storage.db",
                "os.ls",
                "os.cat",
                "os.less",
            ],
        )
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertIsNotNone(load_package_manifest("bywaf.plugins", entry))

    def test_bundled_commandlet_aliases_are_loaded_from_config(self):
        aliases = parse_package_plugin_aliases("bywaf.plugins", "plugins.toml")
        self.assertEqual(aliases["http_tls"], "tls_probe")
        self.assertEqual(aliases["web_fingerprint"], "webfin")

    def test_bundled_sidecar_manifest_traits(self):
        manifest = load_package_manifest("bywaf.plugins", "http.nikto")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlets, frozenset({"nikto"}))
        self.assertFalse(manifest.library_backed)
        self.assertTrue(manifest.process_wrapped)
        self.assertFalse(manifest.native)

    def test_bundled_watchdog_manifest_is_service(self):
        manifest = load_package_manifest("bywaf.plugins", "runtime.watchdog")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlets, frozenset({"watchdog"}))
        self.assertTrue(manifest.service)
        self.assertTrue(manifest.native)

    def test_bundled_db_raw_capability_is_privileged_allowlist_only(self):
        raw_users = {
            name
            for name in self.registry.names()
            if "db.raw" in self.registry.get(name).spec.capabilities
        }
        self.assertEqual(raw_users, {"audit", "db"})

    def test_canonical_manifest_bytes_ignore_order_and_signature_block(self):
        first = {
            "plugin": {"roles": ["beta", "alpha"], "native": True},
            "trusted_keys": ["key-b", "key-a"],
            "commandlets": [
                {"name": "two", "capabilities": ["b", "a"]},
                {"name": "one", "secret_options": ["token", "password"]},
            ],
            "triggers": [
                {
                    "name": "network",
                    "topic": "plugin.capability.used",
                    "action_command": "watchdog --session-service",
                    "exclude_commandlets": ["watchdog", "audit"],
                    "payload_equals": {"b": "2", "a": "1"},
                }
            ],
            "bywaf_signature": {"digest": "old", "signature": "old"},
        }
        second = {
            "bywaf_signature": {"digest": "new", "signature": "new"},
            "triggers": [
                {
                    "payload_equals": {"a": "1", "b": "2"},
                    "exclude_commandlets": ["audit", "watchdog"],
                    "action_command": "watchdog --session-service",
                    "topic": "plugin.capability.used",
                    "name": "network",
                }
            ],
            "commandlets": [
                {"secret_options": ["password", "token"], "name": "one"},
                {"capabilities": ["a", "b"], "name": "two"},
            ],
            "trusted_keys": ["key-a", "key-b"],
            "plugin": {"native": True, "roles": ["alpha", "beta"]},
        }

        self.assertEqual(canonical_manifest_bytes(first), canonical_manifest_bytes(second))
        self.assertEqual(plugin_manifest_digest(first), plugin_manifest_digest(second))

    def test_canonical_manifest_digest_changes_when_values_change(self):
        first = {"commandlets": [{"name": "example", "capabilities": ["network.connect"]}]}
        second = {"commandlets": [{"name": "example", "capabilities": ["filesystem.read"]}]}

        self.assertNotEqual(plugin_manifest_digest(first), plugin_manifest_digest(second))

    def test_bundled_watchdog_provides_network_trigger(self):
        triggers = {trigger.name: trigger for trigger in self.registry.triggers}
        trigger = triggers["network-access-starts-watchdog"]
        self.assertEqual(trigger.topic, "plugin.capability.used")
        self.assertEqual(trigger.capability, "network.connect")
        self.assertEqual(trigger.action_command, "watchdog --session-service")
        self.assertEqual(trigger.action_mode, "service")
        self.assertTrue(trigger.active_job)

    def test_bundled_sidecar_manifest_declares_secret_options(self):
        manifest = load_package_manifest("bywaf.plugins", "network.ssh_probe")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlet_secret_options["ssh_probe"], ("password",))

    def test_bundled_sidecar_manifest_declares_database_actions(self):
        manifest = load_package_manifest("bywaf.plugins", "network.portscanner")
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest.commandlet_database_actions["ports"], ("view",))
        runtime_manifest = load_package_manifest("bywaf.plugins", "runtime.artifact")
        self.assertIsNotNone(runtime_manifest)
        assert runtime_manifest is not None
        self.assertEqual(runtime_manifest.commandlet_database_actions["artifact"], ("view", "write"))
        self.assertEqual(runtime_manifest.commandlet_database_actions["search"], ("view",))
        report_manifest = load_package_manifest("bywaf.plugins", "analysis.report")
        self.assertIsNotNone(report_manifest)
        assert report_manifest is not None
        self.assertEqual(report_manifest.commandlet_database_actions["report"], ("view", "write"))

    def test_registry_tracks_provider_groups(self):
        self.assertEqual(
            self.registry.grouped_names()["analysis"],
            ["finding", "finding_dedupe", "finding_report", "report", "tech_review", "technology_indicators", "yara_scan"],
        )
        self.assertEqual(self.registry.grouped_names()["identity"], ["ldap_probe", "smb_probe"])
        self.assertEqual(
            self.registry.grouped_names()["network"],
            ["management_exposure", "ports", "portscanner", "service_probe", "snmp_get", "ssh_probe", "tcp_banner", "traceroute"],
        )
        self.assertIn("os", self.registry.provider_names())
        self.assertEqual(self.registry.grouped_names()["os"], ["cat", "less", "ls"])
        self.assertEqual(self.registry.grouped_names()["recon"], ["dns_enum", "dns_lookup", "shodan_lookup"])
        self.assertEqual(
            self.registry.grouped_names()["runtime"],
            [
                "artifact",
                "audit",
                "banners",
                "bundle",
                "cancel",
                "certs",
                "end",
                "hosts",
                "job",
                "key",
                "kill",
                "name",
                "note",
                "paths",
                "pause",
                "pipeline",
                "result",
                "results",
                "resume",
                "routes",
                "schemas",
                "screenshots",
                "search",
                "services",
                "shares",
                "signal",
                "step",
                "stop",
                "wafs",
                "watchdog",
                "web",
            ],
        )
        self.assertEqual(self.registry.grouped_names()["storage"], ["db"])

    def test_registry_tracks_provider_qualified_commandlet_aliases(self):
        self.assertIn("http/http_probe", self.registry.commandlet_aliases())
        self.assertIs(self.registry.get("http/http_probe"), self.registry.get("http_probe"))
        self.assertEqual(self.registry.resolve_commandlet_name("http/http_probe"), "http_probe")
        self.assertIn("analysis/technology_indicators/tech_review", self.registry.commandlet_aliases())
        self.assertIs(self.registry.get("analysis/technology_indicators/tech_review"), self.registry.get("tech_review"))
        self.assertEqual(self.registry.resolve_commandlet_name("analysis/technology_indicators/tech_review"), "tech_review")

    def test_web_fingerprint_alias_resolves_to_webfin(self):
        self.assertIn("web_fingerprint", self.registry.commandlet_aliases())
        self.assertIs(self.registry.get("web_fingerprint"), self.registry.get("webfin"))
        self.assertEqual(self.registry.resolve_commandlet_name("web_fingerprint"), "webfin")
        self.assertEqual(self.registry.commandlet_aliases_for("webfin", include_provider=False), ["web_fingerprint"])
        self.assertEqual(self.registry.variable_scope("web_fingerprint"), "http/webfin")

    def test_http_tls_alias_resolves_to_tls_probe(self):
        self.assertIn("http_tls", self.registry.commandlet_aliases())
        self.assertIs(self.registry.get("http_tls"), self.registry.get("tls_probe"))
        self.assertEqual(self.registry.resolve_commandlet_name("http_tls"), "tls_probe")
        self.assertEqual(self.registry.commandlet_aliases_for("tls_probe", include_provider=False), ["http_tls"])
        self.assertEqual(self.registry.variable_scope("http_tls"), "http/tls_probe")

    def test_loads_package_defaults_into_varstore(self):
        self.assertEqual(self.registry.varstore.get("network/portscanner.port"), "")

    def test_get_unknown_raises_clear_key_error(self):
        with self.assertRaisesRegex(KeyError, "unknown commandlet"):
            self.registry.get("missing")
