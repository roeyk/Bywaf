import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.events import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.eyewitness import EyeWitness, eyewitness_argv, eyewitness_output_dir
from bywaf.plugins.wireless.wifi_scan import WifiScan, extract_networks, kismet_argv, wifi_output_dir


class EyeWitnessTests(unittest.TestCase):
    def test_eyewitness_argv_uses_single_or_target_file(self):
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
        context = CommandContext(None, "eyewitness", metadata={"command_run_id": "run-1"})
        self.assertEqual(eyewitness_output_dir(context, ""), Path(".bywaf/eyewitness/run-1"))

    def test_eyewitness_emits_screenshot_events(self):
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

            with patch("bywaf.plugin_process.run_process_argv", side_effect=fake_run):
                list(EyeWitness().run(context, [f"--output-dir={output_dir}"], [event]))

            screenshot = db.events_for_topic("eyewitness.screenshot")[0].payload
            self.assertEqual(screenshot["relative_path"], "screens/example.png")
            self.assertTrue(db.events_for_topic("web.screenshot"))
            self.assertTrue(db.events_for_topic("framework.process.run.requested"))


class WifiScanTests(unittest.TestCase):
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

            with patch("bywaf.plugin_process.run_process_argv", side_effect=fake_run):
                list(WifiScan().run(context, [f"output-dir={output_dir}", "interface=wlan0mon"], []))

            network = db.events_for_topic("wifi.network")[0].payload["network"]
            self.assertEqual(network["ssid"], "Lab")
            self.assertEqual(network["bssid"], "00:11:22:33:44:55")
            self.assertTrue(db.events_for_topic("kismet.network"))


if __name__ == "__main__":
    unittest.main()
