"""Host discovery commandlet."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.nmap_backend import discover_live_hosts
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, split_var_values
from bywaf.utils import host_candidates

DEFAULTS = {"arguments": "-sn", "except": "", "limit": 256, "targets": ""}


@commandlet(
    name="hostscanner",
    description="Discover live hosts with nmap.",
    usage="hostscanner [options] <target> [target ...]",
    examples=(
        "hostscanner 127.0.0.1",
        "hostscanner 192.168.0.1-255",
        "hostscanner 192.168.0.1& | portscanner&",
    ),
    emits=("host.found",),
    capabilities=("framework.console.alert", "network.connect"),
)
@option("arguments", "nmap host discovery arguments", "-sn")
@option("except", "hosts or ranges to exclude", "")
@option("limit", "maximum live hosts to emit", "256")
@option("silent", "suppress discovery alerts", "false")
class HostScanner(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Expand target expressions, run nmap discovery, and emit live hosts."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("--except", dest="except_", default=self.var_default(context, "except", ""))
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--arguments", default=self.var_default(context, "arguments", "-sn"))
        parser.add_argument("--limit", type=int, default=self.var_default(context, "limit", 256, cast=int))
        parsed = parser.parse_args(normalize_except_args(args))
        target_args = self.values_or_var(context, parsed.targets, "targets", required=True)
        targets = expand_targets(target_args, parsed.limit)
        targets = exclude_hosts(targets, parsed.except_)
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
        for host in discover_live_hosts(" ".join(targets), parsed.arguments)[: parsed.limit]:
            context.raise_if_cancelled()
            context.alert(f"discovered host {host}", silent=parsed.silent)
            yield {"host": host, "status": "up", "scanner": "nmap"}


def expand_targets(targets: list[str], limit: int) -> tuple[str, ...]:
    """Expand user-friendly IPv4 ranges while enforcing a safety limit."""
    expanded: list[str] = []
    for target in targets:
        expanded.extend(host_candidates(target))
        if len(expanded) > limit:
            raise ValueError(f"expanded target list exceeds limit {limit}")
    return tuple(expanded)


def normalize_except_args(args: list[str]) -> list[str]:
    """Convert Bywaf-native `except=` selectors into argparse options."""
    normalized: list[str] = []
    for arg in args:
        if arg.startswith("except="):
            normalized.extend(["--except", arg.split("=", 1)[1]])
        else:
            normalized.append(arg)
    return normalized


def exclude_hosts(hosts: Iterable[str], except_value: str) -> tuple[str, ...]:
    """Remove hosts covered by an `except=` host/range list."""
    excluded = {
        host
        for value in split_var_values(except_value)
        for host in host_candidates(value)
    }
    if not excluded:
        return tuple(hosts)
    return tuple(host for host in hosts if host not in excluded)


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HostScanner()
