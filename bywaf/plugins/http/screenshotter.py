"""Screenshotter commandlet backed by EyeWitness.

Provides a friendlier Bywaf commandlet name for the external EyeWitness
screenshot workflow while reusing the audited EyeWitness wrapper.

Consumes:
- `http.endpoint` events or explicit URL arguments.

Emits:
- `eyewitness.screenshot` for raw screenshot files.
- `web.screenshotted_host` for normalized host-to-screenshot artifact groups.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
"""

from __future__ import annotations

from bywaf.plugin import Commandlet, commandlet, option
from bywaf.plugins.http.eyewitness import EyeWitness


@commandlet(
    name="screenshotter",
    description="Capture HTTP endpoint screenshots with EyeWitness.",
    usage="screenshotter [options] [target ...]",
    examples=(
        "screenshotter https://example.test/",
        "http_probe https://example.test/ | screenshotter",
    ),
    consumes=("http.endpoint",),
    emits=("eyewitness.screenshot", "web.screenshotted_host"),
    capabilities=(
        "artifact.write",
        "db.write:eyewitness.screenshot",
        "db.write:web.screenshotted_host",
        "db.write:tool.error",
        "db.write:system.error",
        "filesystem.read",
        "filesystem.write",
        "framework.console.alert",
        "framework.process.run",
        "network.connect",
    ),
)
@option("binary", "EyeWitness executable", "eyewitness", completion="path")
@option("output-dir", "directory for EyeWitness output", completion="path")
@option("silent", "suppress screenshot alerts", "false")
@option("source", "endpoint source", "all", ("all", "explicit"))
@option("timeout", "seconds for the EyeWitness run", "600")
class Screenshotter(EyeWitness):
    """Capture screenshots through the existing EyeWitness wrapper."""


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Screenshotter()
