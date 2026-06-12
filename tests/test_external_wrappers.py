"""Tests for external wrappers behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: external wrappers regression behavior.
- maintainers: document expected behavior through executable examples."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.eyewitness import EyeWitness, eyewitness_argv, eyewitness_output_dir
from bywaf.plugins.wireless.wifi_scan import WifiScan, extract_networks, kismet_argv, wifi_output_dir


class EyeWitnessTests(unittest.TestCase):
    """Groups regression coverage for external wrappers behavior."""
    def test_eyewitness_argv_uses_single_or_target_file(self):
        """Protect eyewitness argv uses single or target file behavior from regressions."""
        one, target_file = eyewitness_argv(
            "eyewitness",
            [{"url": "https://example.test/"}],
            Path("/tmp/eyewitness"),
        )
        self.assertIn("--single", one)
        self.assertIsNone(target_file)

        with tempfile.TemporaryDirectory() as tmp:
            many, target_file = eyewitness_argv(
                "eyewitness",
                [{"url": "https://one.test/"}, {"url": "https://two.test/"}],
                Path(tmp),
            )
            self.assertIn("-f", many)
            self.assertIsNotNone(target_file)
            if target_file is None:
                raise AssertionError("target file was not created")
            self.assertIn("https://two.test/", target_file.read_text())

    def test_default_eyewitness_output_dir_is_durable_bywaf_state(self):
        """Protect default eyewitness output dir is durable bywaf state behavior from regressions."""
        context = CommandContext(None, "eyewitness", metadata={"command_run_id": "run-1"})
        self.assertEqual(eyewitness_output_dir(context, ""), Path(".bywaf/eyewitness/run-1"))

    def test_eyewitness_emits_screenshot_events(self):
        """Protect eyewitness emits screenshot events behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            output_dir = Path(tmp, "eye")
            context = CommandContext(
                db=db,
                source="eyewitness",
                metadata={"command_run_id": "run-1", "capabilities": EyeWitness().spec.capabilities},
            )
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "test")

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                screenshot_dir = Path(argv[argv.index("-d") + 1]) / "screens"
                screenshot_dir.mkdir(parents=True)
                Path(screenshot_dir, "example.png").write_bytes(b"png")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(EyeWitness().run(context, [f"output-dir={output_dir}"], [event]))

            screenshot = db.events_for_topic("eyewitness.screenshot")[0].payload
            self.assertEqual(screenshot["relative_path"], "screens/example.png")
            web_screenshot = db.events_for_topic("web.screenshotted_host")[0].payload
            self.assertEqual(web_screenshot["urls"], ["https://example.test/"])
            self.assertEqual(web_screenshot["screenshots"][0]["file"], str(output_dir / "screens" / "example.png"))
            self.assertTrue(db.events_for_topic("framework.process.run.requested"))

    def test_eyewitness_missing_binary_fails_after_audit_event(self):
        """Protect eyewitness missing binary fails after audit event behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="eyewitness",
                metadata={"command_run_id": "run-1", "capabilities": EyeWitness().spec.capabilities},
            )
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "test")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=FileNotFoundError("eyewitness")):
                with self.assertRaisesRegex(ValueError, "EyeWitness executable not found"):
                    list(EyeWitness().run(context, ["binary=missing-eyewitness"], [event]))

            errors = db.events_for_topic("system.error")
            self.assertEqual(errors[0].payload["message"], "EyeWitness executable not found")

    def test_eyewitness_nonzero_exit_links_process_output_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="eyewitness",
                metadata={"command_run_id": "run-1", "capabilities": EyeWitness().spec.capabilities},
            )
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "test")

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                del argv, cwd, env, timeout
                return subprocess.CompletedProcess([], 3, stdout="partial stdout", stderr="fatal stderr")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(EyeWitness().run(context, [f"output-dir={Path(tmp, 'eye')}"], [event]))

            errors = [event.payload for event in db.events_for_topic("tool.error")]
            exit_error = next(error for error in errors if error["message"] == "EyeWitness exited with status 3")
            self.assertIn("artifact_id", exit_error)
            self.assertIn("partial stdout", exit_error["stdout"])
            self.assertTrue(db.events_for_topic("artifact.attached"))

    def test_eyewitness_timeout_reports_tool_error_without_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="eyewitness",
                metadata={"command_run_id": "run-1", "capabilities": EyeWitness().spec.capabilities},
            )
            event = Event.new("http.endpoint", {"url": "https://example.test/"}, "test")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=subprocess.TimeoutExpired(["eyewitness"], 1)):
                list(EyeWitness().run(context, [f"output-dir={Path(tmp, 'eye')}"], [event]))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["message"], "EyeWitness run timed out")
            self.assertEqual(db.events_for_topic("eyewitness.screenshot"), [])

    def test_eyewitness_value_carrying_output_dir_flag_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = CommandContext(
                db=EventStore(Path(tmp, "bywaf.sqlite3")),
                source="eyewitness",
                metadata={"command_run_id": "run-1", "capabilities": EyeWitness().spec.capabilities},
            )
            with self.assertRaisesRegex(ValueError, "output-dir=path"):
                list(EyeWitness().run(context, [f"--output-dir={Path(tmp, 'eye')}"], []))


class WifiScanTests(unittest.TestCase):
    """Groups regression coverage for external wrappers behavior."""
    def test_kismet_argv_is_shell_free(self):
        argv = kismet_argv("kismet", "wlan0mon", Path("/tmp/kismet"), "kismet,json")
        self.assertEqual(argv[:4], ["kismet", "-c", "wlan0mon", "--no-ncurses"])
        self.assertIn("--log-prefix", argv)
        self.assertIn("--log-types", argv)

    def test_default_wifi_output_dir_is_durable_bywaf_state(self):
        context = CommandContext(None, "wifi_scan", metadata={"command_run_id": "run-1"})
        self.assertEqual(wifi_output_dir(context, ""), Path(".bywaf/wireless/run-1"))

    def test_extract_networks_normalizes_kismet_like_records(self):
        networks = extract_networks(
            {
                "devices": [
                    {
                        "kismet.device.base.name": "CorpWiFi",
                        "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:ff",
                        "kismet.device.base.channel": "6",
                    }
                ]
            }
        )
        self.assertEqual(networks[0]["ssid"], "CorpWiFi")
        self.assertEqual(networks[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(networks[0]["channel"], "6")

    def test_wifi_scan_emits_network_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            output_dir = Path(tmp, "wifi")
            context = CommandContext(
                db=db,
                source="wifi_scan",
                metadata={"command_run_id": "run-1", "capabilities": WifiScan().spec.capabilities},
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                log_prefix = Path(argv[argv.index("--log-prefix") + 1])
                log_prefix.parent.mkdir(parents=True, exist_ok=True)
                Path(f"{log_prefix}.json").write_text(
                    json.dumps({"networks": [{"ssid": "Lab", "bssid": "00:11:22:33:44:55"}]}),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(WifiScan().run(context, [f"output-dir={output_dir}", "interface=wlan0mon"], []))

            network = db.events_for_topic("wifi.network")[0].payload["network"]
            self.assertEqual(network["ssid"], "Lab")
            self.assertEqual(network["bssid"], "00:11:22:33:44:55")
            self.assertTrue(db.events_for_topic("kismet.network"))

    def test_wifi_scan_nonzero_exit_links_process_output_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="wifi_scan",
                metadata={"command_run_id": "run-1", "capabilities": WifiScan().spec.capabilities},
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                del argv, cwd, env, timeout
                return subprocess.CompletedProcess([], 2, stdout="scan stdout", stderr="scan stderr")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(WifiScan().run(context, ["output-dir=" + str(Path(tmp, "wifi")), "interface=wlan0mon"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["message"], "Kismet exited with status 2")
            self.assertIn("artifact_id", error)
            self.assertIn("scan stderr", error["stderr"])

    def test_wifi_scan_timeout_is_informational_stop_without_networks(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="wifi_scan",
                metadata={"command_run_id": "run-1", "capabilities": WifiScan().spec.capabilities},
            )

            with patch("bywaf.plugin.process.run_process_argv", side_effect=subprocess.TimeoutExpired(["kismet"], 1)):
                list(WifiScan().run(context, ["output-dir=" + str(Path(tmp, "wifi")), "interface=wlan0mon"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["severity"], "info")
            self.assertEqual(error["message"], "Kismet scan stopped after requested duration")
            self.assertEqual(db.events_for_topic("wifi.network"), [])


if __name__ == "__main__":
    unittest.main()
