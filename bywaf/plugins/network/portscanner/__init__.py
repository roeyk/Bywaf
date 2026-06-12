"""Port scanning commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for nmap
port scanning.

Consumes:
- `host.found` events or explicit command arguments.

Emits:
- `port.open` for discovered open ports.
- `finding.candidate` for risky exposed services.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from importlib import import_module
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugins.addressing import filter_by_ip_family, is_ip_scan_target, target_matches_ip_family
from bywaf.plugins.discovery.hostscanner import publish_name_resolution_events
from bywaf.plugins.network.nmap_diagnostics import NMAP_FAILURES, publish_nmap_error
from bywaf.plugins.network.nmap_backend import scan_open_ports
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool, split_var_values
from bywaf.plugin import kv_to_args
from bywaf.plugins.network.portscanner.findings import telnet_open_candidate

DEFAULTS = {
    "arguments": "-sT",
    "except": "",
    "host": "",
    "listen": "false",
    "listen-interval": "1.0",
    "listen-timeout": "0",
    "port": "",
    "silent": "false",
}


@commandlet(
    name="portscanner",
    description="Scan TCP ports with nmap for hosts from args or pipeline input.",
    usage="portscanner [options] [host ...]",
    examples=(
        "hostscanner 127.0.0.1 | portscanner",
        "portscanner port=22,80,443 host=127.0.0.1",
        "hostscanner 192.168.0.1-255& | portscanner&",
    ),
)
@option("arguments", "nmap port scan arguments", "-sT")
@option("except", "hosts to exclude from scans", "")
@option("host", "single explicit host to scan", "")
@option("listen", "poll scoped upstream host.found events", "false")
@option("listen-interval", "poll interval in seconds", "1.0")
@option("listen-timeout", "seconds to listen; 0 means forever", "0")
@option("port", "optional comma/range port list; omit for nmap top ports")
@option("silent", "suppress discovery alerts", "false")
class PortScanner(CommandletBase):
    """Commandlet that scans target ports and emits open-port facts."""
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Scan explicit/pipeline hosts, then optionally listen for new hosts."""
        parser = self.parser()
        parser.add_argument("hosts", nargs="*")
        parser.add_argument("--host", dest="host_option", default=self.var_default(context, "host", ""))
        parser.add_argument("--except", dest="except_", default=self.var_default(context, "except", ""))
        parser.add_argument(
            "-s",
            "--silent",
            "--quiet",
            action="store_true",
            default=self.var_default(context, "silent", False, cast=parse_bool),
        )
        parser.add_argument("--arguments", default=self.var_default(context, "arguments", "-sT"))
        parser.add_argument("--listen", action="store_true", default=self.var_default(context, "listen", False, cast=parse_bool))
        parser.add_argument("--listen-interval", type=float, default=self.var_default(context, "listen-interval", 1.0, cast=float))
        parser.add_argument("--listen-timeout", type=float, default=self.var_default(context, "listen-timeout", 0.0, cast=float))
        parser.add_argument("--port", dest="port_option", default=self.var_default(context, "port", None))
        # Compatibility alias for older scripts.  The advertised Bywaf syntax is
        # `port=...`, mirroring `host=...`.
        parser.add_argument("--ports", dest="port_option")
        parsed = parser.parse_args(normalize_value_args(args))
        parsed.hosts = explicit_hosts_or_var(parsed.hosts, parsed.host_option)
        parsed.excluded_hosts = set(split_var_values(parsed.except_))
        seen_hosts: set[str] = set()
        yield from scan_events_or_hosts(context, parsed, input_events, seen_hosts)
        should_listen = parsed.listen or (
            bool(context.parent_command_run_id)
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
    # Direct CLI hosts are operator intent and win over pipeline input.  If no
    # hosts were provided, this commandlet acts as a normal downstream consumer
    # of `host.found` events.
    hosts = parsed.hosts or [event.payload["host"] for event in input_events if event.topic == "host.found" and "host" in event.payload]
    if not hosts and context.parent_command_run_id:
        context.output("portscanner: no host.found input from upstream; use hostscanner ... | portscanner or pass host=<target>")
    if parsed.hosts:
        hosts = resolve_explicit_hosts(context, hosts, parsed.arguments)
    hosts = [host for host in hosts if host not in parsed.excluded_hosts]
    yield from scan_hosts(context, hosts, parsed.port_option, parsed.arguments, seen_hosts, parsed.silent)


def resolve_explicit_hosts(context: CommandContext, hosts: Iterable[str], arguments: str) -> list[str]:
    """Resolve explicit host names before scanning and record provenance."""
    resolved: list[str] = []
    names_by_host: dict[str, str] = {}
    for host in hosts:
        if is_ip_scan_target(host):
            if target_matches_ip_family(host, arguments):
                resolved.append(host)
            else:
                context.alert(f"scan target {host} does not match nmap address-family arguments")
            continue
        addresses = filter_by_ip_family(context.policy.resolve_target(host), arguments)
        if not addresses:
            context.alert(f"no resolved addresses for {host} match nmap address-family arguments")
            continue
        resolved.extend(addresses)
        if addresses != (host,):
            context.output(f"resolved host {host} -> {', '.join(addresses)}")
            for address in addresses:
                names_by_host[address] = host
    publish_name_resolution_events(context, names_by_host)
    return list(dict.fromkeys(resolved))


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
    new_hosts = filter_hosts_by_policy(context, new_hosts)
    if not new_hosts:
        return
    context.raise_if_cancelled()
    seen_hosts.update(new_hosts)
    context.audit_capability("network.connect")
    # Progress events are scoped around the nmap call, not around every yielded
    # port.  UI/reporting layers get one operation boundary, followed by
    # individual `port.open` facts as results.
    context.progress_started(
        phase="port_scan",
        total=len(new_hosts),
        unit="hosts",
        message="port scan started",
        ports=ports or "",
        arguments=arguments,
    )
    try:
        open_ports = scan_open_ports(new_hosts, ports, arguments)
    except NMAP_FAILURES as exc:
        publish_nmap_error(context, exc, phase="port_scan")
        context.progress_failed(
            phase="port_scan",
            message="port scan failed",
            error=str(exc),
            ports=ports or "",
            arguments=arguments,
        )
        return
    context.progress_completed(
        phase="port_scan",
        current=len(new_hosts),
        total=len(new_hosts),
        unit="hosts",
        message="port scan completed",
        open_ports=len(open_ports),
        ports=ports or "",
        arguments=arguments,
    )
    for port in open_ports:
        context.raise_if_cancelled()
        context.alert(
            f"discovered port {port.port}/{port.protocol} on host {port.host}",
            silent=silent,
        )
        payload = {
            "host": port.host,
            "port": port.port,
            "protocol": port.protocol,
            "state": port.state,
            "service": port.service,
            "reason": port.reason,
            "scanner": "nmap",
        }
        # Plain open ports are facts.  Only clearly risk-relevant facts are
        # promoted into finding candidates here; later plugins can add richer
        # confirmation findings.
        candidate = telnet_open_candidate(payload)
        if candidate:
            context.events.publish("finding.candidate", candidate)
        yield payload


def filter_hosts_by_policy(context: CommandContext, hosts: Iterable[str]) -> list[str]:
    """Apply framework network policy before invoking the port scanner."""
    return list(context.policy.filter_network_targets(hosts))


def listen_for_upstream_hosts(context: CommandContext, parsed, seen_hosts: set[str]):
    """Poll only the upstream pipeline step from the same pipeline.

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
        # Live listeners must still honor exclusions and dedupe; otherwise a
        # noisy upstream scanner could repeatedly rescan the same host or a host
        # the operator removed from scope mid-workflow.
        if "host" not in event.payload or event.payload["host"] in parsed.excluded_hosts:
            continue
        yield from scan_hosts(
            context,
            [event.payload["host"]],
            parsed.port_option,
            parsed.arguments,
            seen_hosts,
            parsed.silent,
        )


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return PortScanner()


def plugins() -> tuple[Commandlet, ...]:
    """Factory used when the portscanner provider exposes helper views too."""
    # The `ports` view lives in a child package. Import it lazily here so the
    # bundled provider can expose both commandlets without creating a static
    # parent<->child import cycle in architecture metrics.
    ports_module = import_module("bywaf.plugins.network.portscanner.ports")
    Ports = ports_module.Ports
    return (PortScanner(), Ports())


VALUE_OPTION_KEYS = {"arguments", "except", "host", "listen-interval", "listen-timeout", "port", "ports"}


def normalize_value_args(args: list[str]) -> list[str]:
    """Convert supported Bywaf `key=value` tokens into argparse options."""
    return kv_to_args(args, VALUE_OPTION_KEYS)


def explicit_hosts_or_var(positional_hosts: list[str], option_host: str) -> list[str]:
    """Return explicit positional/host option values, falling back to variables."""
    explicit_hosts = list(positional_hosts)
    explicit_hosts.extend(split_var_values(option_host))
    return explicit_hosts
