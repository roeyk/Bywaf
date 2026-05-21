"""Port scanning commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Consumes hosts and emits network service events from port scan results.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from bywaf.events import Event
from bywaf.nmap_backend import scan_open_ports
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, split_var_values

DEFAULTS = {
    "arguments": "-sT",
    "except": "",
    "hosts": "",
    "listen": "false",
    "listen-interval": "1.0",
    "listen-timeout": "0",
    "ports": "",
    "silent": "false",
}


@commandlet(
    name="portscanner",
    description="Scan TCP ports with nmap for hosts from args or pipeline input.",
    usage="portscanner [options] [host ...]",
    examples=(
        "hostscanner 127.0.0.1 | portscanner",
        "portscanner --ports 22,80,443 127.0.0.1",
        "hostscanner 192.168.0.1-255& | portscanner&",
    ),
    consumes=("host.found",),
    emits=("port.open",),
    capabilities=("framework.console.alert", "network.connect"),
)
@option("arguments", "nmap port scan arguments", "-sT")
@option("except", "hosts to exclude from scans", "")
@option("listen", "poll scoped upstream host.found events", "false")
@option("listen-interval", "poll interval in seconds", "1.0")
@option("listen-timeout", "seconds to listen; 0 means forever", "0")
@option("ports", "optional comma/range port list; omit for nmap top ports")
@option("silent", "suppress discovery alerts", "false")
class PortScanner(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Scan explicit/pipeline hosts, then optionally listen for new hosts."""
        parser = self.parser()
        parser.add_argument("hosts", nargs="*")
        parser.add_argument("--except", dest="except_", default=self.var_default(context, "except", ""))
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--arguments", default=self.var_default(context, "arguments", "-sT"))
        parser.add_argument("--listen", action="store_true", default=self.var_default(context, "listen", False, cast=parse_bool))
        parser.add_argument("--listen-interval", type=float, default=self.var_default(context, "listen-interval", 1.0, cast=float))
        parser.add_argument("--listen-timeout", type=float, default=self.var_default(context, "listen-timeout", 0.0, cast=float))
        parser.add_argument("--ports", default=self.var_default(context, "ports", None))
        parsed = parser.parse_args(normalize_except_args(args))
        parsed.hosts = self.values_or_var(context, parsed.hosts, "hosts")
        parsed.excluded_hosts = set(split_var_values(parsed.except_))
        seen_hosts: set[str] = set()
        yield from scan_events_or_hosts(context, parsed, input_events, seen_hosts)
        should_listen = parsed.listen or (
            context.background
            and bool(context.parent_command_run_id)
            and not parsed.hosts
        )
        if should_listen:
            yield from listen_for_upstream_hosts(context, parsed, seen_hosts)


def scan_events_or_hosts(
    context: CommandContext,
    parsed,
    input_events: Iterable[Event],
    seen_hosts: set[str],
):
    """Choose explicit hosts first, otherwise consume upstream host events."""
    hosts = parsed.hosts or [event.payload["host"] for event in input_events if "host" in event.payload]
    hosts = [host for host in hosts if host not in parsed.excluded_hosts]
    yield from scan_hosts(context, hosts, parsed.ports, parsed.arguments, seen_hosts, parsed.silent)


def scan_hosts(
    context: CommandContext,
    hosts: Iterable[str],
    ports: str | None,
    arguments: str,
    seen_hosts: set[str],
    silent: bool,
):
    """Scan hosts once and emit normalized open-port payloads."""
    new_hosts = [host for host in hosts if host and host not in seen_hosts]
    if not new_hosts:
        return
    context.raise_if_cancelled()
    seen_hosts.update(new_hosts)
    context.audit_capability("network.connect")
    for port in scan_open_ports(new_hosts, ports, arguments):
        context.raise_if_cancelled()
        context.alert(
            f"discovered port {port.port}/{port.protocol} on host {port.host}",
            silent=silent,
        )
        yield {
            "host": port.host,
            "port": port.port,
            "protocol": port.protocol,
            "state": port.state,
            "service": port.service,
            "reason": port.reason,
            "scanner": "nmap",
        }


def listen_for_upstream_hosts(context: CommandContext, parsed, seen_hosts: set[str]):
    """Poll only the upstream command run from the same pipeline.

    This is what makes `hostscanner ... & | portscanner &` scoped: the port
    scanner ignores global `host.found` events from unrelated runs.
    """
    upstream_id = context.parent_command_run_id
    pipeline_id = context.pipeline_id
    if not pipeline_id:
        raise ValueError("portscanner --listen must be used in a pipeline scope")
    for event in context.events.follow(
            ("host.found",),
            after_id=context.input_high_watermark,
            pipeline_id=pipeline_id,
            command_run_id=upstream_id,
            until_parent_done=True,
            idle_interval=parsed.listen_interval,
            timeout=parsed.listen_timeout if parsed.listen_timeout > 0 else None,
    ):
        if "host" not in event.payload or event.payload["host"] in parsed.excluded_hosts:
            continue
        yield from scan_hosts(
            context,
            [event.payload["host"]],
            parsed.ports,
            parsed.arguments,
            seen_hosts,
            parsed.silent,
        )


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return PortScanner()


def normalize_except_args(args: list[str]) -> list[str]:
    """Convert Bywaf-native `except=` selectors into argparse options."""
    normalized: list[str] = []
    for arg in args:
        if arg.startswith("except="):
            normalized.extend(["--except", arg.split("=", 1)[1]])
        else:
            normalized.append(arg)
    return normalized


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}
