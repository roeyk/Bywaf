"""Host discovery commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for nmap
host discovery.

Consumes:
- command arguments and configured discovery targets.

Emits:
- `host.found` for discovered live hosts.
- `name.resolved` when DNS names resolve to concrete hosts.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.event import Event
from bywaf.policy import resolve_target
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.network.nmap_diagnostics import NMAP_FAILURES, publish_nmap_error
from bywaf.plugins.network.nmap_backend import discover_live_hosts
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, PlanItem, PlanRepair, PlanReport, commandlet, option, parse_bool, split_var_values
from bywaf.utils import host_candidates

DEFAULTS = {"arguments": "-sn", "except": "", "host": "", "limit": 256, "targets": ""}
VALUE_OPTION_KEYS = {"arguments", "except", "host", "limit"}


@dataclass(frozen=True, slots=True)
class HostScannerIntent:
    """Normalized hostscanner action used by planning and execution."""

    targets: tuple[str, ...]
    arguments: str
    options: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExpandedTargets:
    """Concrete scan targets plus hostname provenance."""

    hosts: tuple[str, ...]
    names_by_host: dict[str, str]


@commandlet(
    name="hostscanner",
    description="Discover live hosts with nmap.",
    usage="hostscanner [options] <target> [target ...]",
    examples=(
        "hostscanner 127.0.0.1",
        "hostscanner 192.168.0.1-255",
        "hostscanner 192.168.0.1& | portscanner&",
    ),
)
@option("arguments", "nmap host discovery arguments", "-sn")
@option("except", "hosts or ranges to exclude", "")
@option("host", "single explicit host, name, range, or CIDR to discover", "")
@option("limit", "maximum live hosts to emit", "256")
@option("silent", "suppress discovery alerts", "false")
class HostScanner(CommandletBase):
    def plan(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> PlanReport:
        """Describe host discovery targets and policy warnings before scanning."""
        del input_events
        intent = hostscanner_intent(self, context, args)
        _allowed, _denied, mode = context.policy.network_policy()
        allowed_targets, warnings = context.policy.evaluate_network_targets(intent.targets)
        repairs: tuple[PlanRepair, ...] = ()
        if warnings and allowed_targets:
            patched_args = tuple([*intent.options, *allowed_targets])
            repairs = (
                PlanRepair(
                    "prune-out-of-scope",
                    "Prune denied or out-of-scope targets for this run only.",
                    patched_args,
                    before={"targets": list(intent.targets)},
                    after={"targets": list(allowed_targets)},
                ),
            )
        if warnings and not allowed_targets and mode == "strict":
            warnings = [*warnings, "No targets remain after policy evaluation."]
        return PlanReport(
            "scan-hosts",
            f"Scan {len(intent.targets)} host target(s) with nmap arguments {intent.arguments!r}.",
            items=tuple(PlanItem("target", target) for target in intent.targets),
            warnings=tuple(warnings),
            repairs=repairs,
            requires_confirmation=bool(warnings) or plan_required(context),
        )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Expand target expressions, run nmap discovery, and emit live hosts."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("--host", dest="host_option", default=self.var_default(context, "host", ""))
        parser.add_argument("--except", dest="except_", default=self.var_default(context, "except", ""))
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--arguments", default=self.var_default(context, "arguments", "-sn"))
        parser.add_argument("--limit", type=int, default=self.var_default(context, "limit", 256, cast=int))
        parsed = parser.parse_args(normalize_value_args(args))
        target_args = explicit_targets_or_var(self, context, parsed.targets, parsed.host_option)
        # Target expansion is separated from the nmap call so policy planning,
        # DNS name capture, exclusions, and limits all operate on the same
        # normalized target set.
        expanded_targets = cached_target_details(context, target_args, parsed.limit)
        targets = expanded_targets.hosts
        targets = exclude_hosts(targets, parsed.except_)
        names_by_host = {host: name for host, name in expanded_targets.names_by_host.items() if host in targets}
        publish_name_resolution_events(context, names_by_host)
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
        try:
            live_hosts = discover_live_hosts(" ".join(targets), parsed.arguments)
        except NMAP_FAILURES as exc:
            publish_nmap_error(context, exc, phase="host_discovery")
            context.output(f"error: {exc}")
            return
        for host in live_hosts[: parsed.limit]:
            context.raise_if_cancelled()
            context.alert(f"discovered host {host}", silent=parsed.silent)
            event: dict[str, object] = {"host": host, "status": "up", "scanner": "nmap"}
            # Keep discovered DNS/name context beside the host fact so
            # downstream commandlets and reports do not need to join against
            # separate name-resolution events for the common case.
            if host in names_by_host:
                event["name"] = names_by_host[host]
            yield event


def hostscanner_intent(commandlet: HostScanner, context: CommandContext, args: list[str]) -> HostScannerIntent:
    """Parse hostscanner arguments and return normalized intended targets."""
    parser = commandlet.parser()
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--host", dest="host_option", default=commandlet.var_default(context, "host", ""))
    parser.add_argument("--except", dest="except_", default=commandlet.var_default(context, "except", ""))
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--arguments", default=commandlet.var_default(context, "arguments", "-sn"))
    parser.add_argument("--limit", type=int, default=commandlet.var_default(context, "limit", 256, cast=int))
    parsed = parser.parse_args(normalize_value_args(args))
    target_args = explicit_targets_or_var(commandlet, context, parsed.targets, parsed.host_option)
    targets = exclude_hosts(cached_target_details(context, target_args, parsed.limit).hosts, parsed.except_)
    options: list[str] = [f"--arguments={parsed.arguments}", f"--limit={parsed.limit}"]
    if parsed.silent:
        options.append("--silent")
    if parsed.except_:
        options.extend(["--except", parsed.except_])
    return HostScannerIntent(targets, parsed.arguments, tuple(options))


def expand_targets(targets: list[str], limit: int) -> tuple[str, ...]:
    """Expand user-friendly target expressions while enforcing a safety limit."""
    return expand_target_details(targets, limit).hosts


def cached_target_details(
    context: CommandContext,
    targets: list[str],
    limit: int,
) -> ExpandedTargets:
    """Return per-command cached target expansion details."""
    cache = context.metadata.setdefault("_hostscanner_target_cache", {})
    key = (tuple(targets), limit)
    if key not in cache:
        cache[key] = expand_target_details(targets, limit, resolver=context.policy.resolve_target)
    return cache[key]


def expand_target_details(targets: list[str], limit: int, *, resolver=resolve_target) -> ExpandedTargets:
    """Expand IP ranges and hostnames into concrete scan targets."""
    expanded: list[str] = []
    names_by_host: dict[str, str] = {}
    for target in targets:
        for candidate in host_candidates(target):
            addresses = resolver(candidate)
            expanded.extend(addresses)
            for address in addresses:
                if address != candidate:
                    names_by_host[address] = candidate
        if len(expanded) > limit:
            raise ValueError(f"expanded target list exceeds limit {limit}")
    return ExpandedTargets(tuple(dict.fromkeys(expanded)), names_by_host)


def publish_name_resolution_events(context: CommandContext, names_by_host: dict[str, str]) -> None:
    """Record DNS resolution provenance for scan targets."""
    if context._db is None:
        return
    for address, name in names_by_host.items():
        context.events.publish(
            "name.resolved",
            {
                "name": name,
                "host": address,
                "resolver": "system",
                "job_id": context.job_id,
            },
        )


def normalize_value_args(args: list[str]) -> list[str]:
    """Convert supported Bywaf `key=value` tokens into argparse options."""
    return key_value_to_long_options(args, VALUE_OPTION_KEYS)


def explicit_targets_or_var(commandlet: HostScanner, context: CommandContext, targets: list[str], host_option: str) -> list[str]:
    """Return explicit target values, falling back through host then targets vars."""
    explicit_targets = [*targets, *split_var_values(host_option)]
    if explicit_targets:
        return explicit_targets
    host_values = split_var_values(str(context.vars.get("host") or ""))
    if host_values:
        return host_values
    return commandlet.values_or_var(context, (), "targets", required=True)


def exclude_hosts(hosts: Iterable[str], except_value: str) -> tuple[str, ...]:
    """Remove hosts covered by an `except=` host/range list."""
    excluded = {
        host
        for value in split_var_values(except_value)
        for host in expand_targets([value], DEFAULTS["limit"])
    }
    if not excluded:
        return tuple(hosts)
    return tuple(host for host in hosts if host not in excluded)


def plan_required(context: CommandContext) -> bool:
    """Return global policy for requiring plan approval."""
    return parse_bool(context.vars.get_global("plan.required", "false") or "false")


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HostScanner()
