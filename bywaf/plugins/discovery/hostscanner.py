"""Host discovery commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.nmap_backend import discover_live_hosts
from bywaf.plugin import CommandContext, CommandSpec, Commandlet, OptionSpec, emit_alert
from bywaf.utils import host_candidates

DEFAULTS = {"arguments": "-sn", "limit": 256}


class HostScanner:
    spec = CommandSpec(
        name="hostscanner",
        description="Discover live hosts with nmap.",
        usage="hostscanner [options] <target> [target ...]",
        examples=(
            "hostscanner 127.0.0.1",
            "hostscanner 192.168.0.1-255",
            "hostscanner 192.168.0.1& | portscanner&",
        ),
        options=(
            OptionSpec("arguments", "nmap host discovery arguments", "-sn"),
            OptionSpec("limit", "maximum live hosts to emit", "256"),
            OptionSpec("silent", "suppress discovery alerts", "false"),
        ),
        emits=("host.found",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("targets", nargs="+")
        parser.add_argument("-s", "--silent", action="store_true")
        parser.add_argument("--arguments", default="-sn")
        parser.add_argument("--limit", type=int, default=256)
        parsed = parser.parse_args(args)
        targets = expand_targets(parsed.targets, parsed.limit)
        for host in discover_live_hosts(" ".join(targets), parsed.arguments)[: parsed.limit]:
            emit_alert(context, f"discovered host {host}", silent=parsed.silent)
            yield {"host": host, "status": "up", "scanner": "nmap"}


def expand_targets(targets: list[str], limit: int) -> tuple[str, ...]:
    expanded: list[str] = []
    for target in targets:
        expanded.extend(host_candidates(target))
        if len(expanded) > limit:
            raise ValueError(f"expanded target list exceeds limit {limit}")
    return tuple(expanded)


def plugin() -> Commandlet:
    return HostScanner()
