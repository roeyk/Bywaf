"""Kismet-style wireless scanner wrapper commandlet."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from bywaf.config import Settings
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options

DEFAULTS = {
    "binary": "kismet",
    "duration": "60",
    "interface": "",
    "log-types": "kismet,json",
    "output-dir": "",
    "silent": "false",
}
OPTION_KEYS = {"binary", "duration", "interface", "log-types", "output-dir"}


@commandlet(
    name="wifi_scan",
    description="Run a Kismet-style wireless scan and emit Wi-Fi network events.",
    usage="wifi_scan interface=IFACE [duration=SECONDS]",
    examples=(
        "wifi_scan interface=wlan0mon duration=60",
        "vars wifi_scan.interface=wlan0mon",
    ),
    emits=("wifi.network", "kismet.network"),
    capabilities=(
        "artifact.write",
        "db.write:kismet.network",
        "db.write:wifi.network",
        "db.write:tool.error",
        "db.write:system.error",
        "filesystem.read",
        "filesystem.write",
        "framework.console.alert",
        "framework.process.run",
        "network.listen",
        "process.run",
    ),
)
@option("binary", "Kismet executable", "kismet", completion="path")
@option("duration", "scan duration seconds", "60")
@option("interface", "wireless capture interface")
@option("log-types", "Kismet log types", "kismet,json")
@option("output-dir", "directory for Kismet output", completion="path")
@option("silent", "suppress network alerts", "false")
class WifiScan(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run Kismet and publish discovered Wi-Fi networks from JSON output."""
        del input_events
        parser = self.parser()
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--binary", default=self.var_default(context, "binary", "kismet"))
        parser.add_argument("--duration", type=float, default=self.var_default(context, "duration", 60, cast=float))
        parser.add_argument("--interface", default=self.var_default(context, "interface", ""))
        parser.add_argument("--log-types", default=self.var_default(context, "log-types", "kismet,json"))
        parser.add_argument("--output-dir", default=self.var_default(context, "output-dir", ""))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))

        if not parsed.interface:
            context.events.publish(
                "tool.error",
                {
                    "tool": "kismet",
                    "severity": "error",
                    "message": "wifi_scan requires --interface or vars wifi_scan.interface=<iface>",
                },
            )
            return ()

        output_dir = wifi_output_dir(context, str(parsed.output_dir or ""))
        run_wifi_scan(context, parsed, output_dir)
        return ()


def run_wifi_scan(context: CommandContext, parsed: Any, output_dir: Path) -> None:
    """Run Kismet, attach produced logs, and publish network events."""
    context.audit_capability("network.listen")
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = kismet_argv(
        binary=str(parsed.binary),
        interface=str(parsed.interface),
        output_dir=output_dir,
        log_types=str(parsed.log_types),
    )
    timeout = float(parsed.duration) if float(parsed.duration) > 0 else None
    try:
        result = context.process.run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        result = None
        context.events.publish(
            "tool.error",
            {
                "tool": "kismet",
                "severity": "info",
                "message": "Kismet scan stopped after requested duration",
                "duration": parsed.duration,
            },
        )
    except FileNotFoundError as exc:
        publish_tool_problem(context, "system.error", "kismet", "Kismet executable not found", exc)
        return
    except OSError as exc:
        publish_tool_problem(context, "system.error", "kismet", "could not execute Kismet", exc)
        return

    if result is not None and not result.ok:
        context.events.publish(
            "tool.error",
            {
                "tool": "kismet",
                "severity": "error",
                "message": f"Kismet exited with status {result.returncode}",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        )

    attached = attach_output_files(context, output_dir)
    networks = networks_from_output(output_dir)
    for network in networks:
        payload = {
            "tool": "kismet",
            "interface": parsed.interface,
            "network": network,
            "artifacts": attached,
        }
        context.events.publish("kismet.network", payload)
        context.events.publish("wifi.network", payload)
        context.alert(f"discovered Wi-Fi network {display_network(network)}", level="finding", silent=bool(parsed.silent))


def kismet_argv(binary: str, interface: str, output_dir: Path, log_types: str) -> list[str]:
    """Build a shell-free Kismet argv vector."""
    prefix = output_dir / "bywaf-kismet"
    return [
        binary,
        "-c",
        interface,
        "--no-ncurses",
        "--log-prefix",
        str(prefix),
        "--log-types",
        log_types,
    ]


def wifi_output_dir(context: CommandContext, explicit: str) -> Path:
    """Return a durable output directory for wireless scanner logs."""
    if explicit:
        return Path(explicit).expanduser()
    run_id = context.command_run_id or str(context.job_id or "session")
    return Settings().state_dir / "wireless" / run_id


def attach_output_files(context: CommandContext, output_dir: Path) -> list[dict[str, Any]]:
    """Attach Kismet output files when artifact storage is available."""
    attached: list[dict[str, Any]] = []
    for path in output_files(output_dir):
        context.audit_capability("filesystem.read")
        try:
            artifact = context.artifacts.attach_file(path, name=f"kismet-{path.name}", note="Kismet scan output")
        except (RuntimeError, ValueError) as exc:
            context.events.publish(
                "tool.error",
                {
                    "tool": "kismet",
                    "severity": "warning",
                    "message": "Kismet output was not attached as an artifact",
                    "file": str(path),
                    "error": str(exc),
                },
            )
            continue
        attached.append({"artifact_id": artifact.artifact_id, "name": artifact.name, "sha256": artifact.sha256})
    return attached


def output_files(output_dir: Path) -> list[Path]:
    """Return files produced under the Kismet output directory."""
    if not output_dir.exists():
        return []
    return sorted(path for path in output_dir.rglob("*") if path.is_file())


def networks_from_output(output_dir: Path) -> list[dict[str, Any]]:
    """Extract Wi-Fi networks from JSON output files when present."""
    networks: list[dict[str, Any]] = []
    for path in output_dir.rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        networks.extend(extract_networks(data))
    return dedupe_networks(networks)


def extract_networks(data: Any) -> list[dict[str, Any]]:
    """Extract network-like dictionaries from common Kismet JSON layouts."""
    if isinstance(data, list):
        networks: list[dict[str, Any]] = []
        for item in data:
            networks.extend(extract_networks(item))
        return networks
    if not isinstance(data, dict):
        return []

    for key in ("networks", "devices", "kismet.devices"):
        value = data.get(key)
        if isinstance(value, list):
            return [normalize_network(item) for item in value if isinstance(item, dict)]
    if looks_like_network(data):
        return [normalize_network(data)]

    networks: list[dict[str, Any]] = []
    for value in data.values():
        if isinstance(value, (dict, list)):
            networks.extend(extract_networks(value))
    return networks


def looks_like_network(data: dict[str, Any]) -> bool:
    """Return whether a dict resembles a wireless network/device record."""
    keys = {key.lower() for key in data}
    return bool(keys & {"ssid", "bssid", "mac", "kismet.device.base.macaddr", "kismet.device.base.name"})


def normalize_network(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize common Kismet network fields."""
    ssid = first_value(data, "ssid", "kismet.device.base.name", "dot11.device.last_beaconed_ssid")
    bssid = first_value(data, "bssid", "mac", "kismet.device.base.macaddr")
    channel = first_value(data, "channel", "kismet.device.base.channel")
    encryption = first_value(data, "encryption", "crypt", "dot11.device.crypt_set")
    signal = first_value(data, "signal", "kismet.common.signal.last_signal")
    return {
        "ssid": ssid,
        "bssid": bssid,
        "channel": channel,
        "encryption": encryption,
        "signal": signal,
        "raw": data,
    }


def first_value(data: dict[str, Any], *keys: str) -> Any:
    """Return the first present non-empty field from a dict."""
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return ""


def dedupe_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate networks by BSSID then SSID."""
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for network in networks:
        marker = (str(network.get("bssid") or ""), str(network.get("ssid") or ""))
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(network)
    return deduped


def display_network(network: dict[str, Any]) -> str:
    """Return a concise display label for a network."""
    ssid = str(network.get("ssid") or "<hidden>")
    bssid = str(network.get("bssid") or "unknown-bssid")
    return f"{ssid} ({bssid})"


def publish_tool_problem(context: CommandContext, topic: str, tool: str, message: str, exc: BaseException) -> None:
    """Publish a normalized operational problem for an external wrapper."""
    context.events.publish(
        topic,
        {
            "tool": tool,
            "severity": "error",
            "message": message,
            "exception": exc.__class__.__name__,
            "error": str(exc),
        },
    )


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return WifiScan()
