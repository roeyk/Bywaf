"""Host discovery commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Discovers hosts and emits host.found events for downstream network plugins.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bywaf.events import Event
from bywaf.nmap_backend import discover_live_hosts
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, PlanItem, PlanRepair, PlanReport, commandlet, option, split_var_values
from bywaf.utils import host_candidates

DEFAULTS = {"arguments": "-sn", "except": "", "limit": 256, "targets": ""}


@dataclass(frozen=True, slots=True)
class HostScannerIntent:
    """Normalized hostscanner action used by planning and execution."""

    targets: tuple[str, ...]
    arguments: str
    options: tuple[str, ...]


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
    def plan(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> PlanReport:
        """Describe host discovery targets and policy warnings before scanning."""
        del input_events
        intent = hostscanner_intent(self, context, args)
        allowed, denied, mode = network_policy(context)
        allowed_targets, warnings = apply_network_policy(intent.targets, allowed, denied)
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


def hostscanner_intent(commandlet: HostScanner, context: CommandContext, args: list[str]) -> HostScannerIntent:
    """Parse hostscanner arguments and return normalized intended targets."""
    parser = commandlet.parser()
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--except", dest="except_", default=commandlet.var_default(context, "except", ""))
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--arguments", default=commandlet.var_default(context, "arguments", "-sn"))
    parser.add_argument("--limit", type=int, default=commandlet.var_default(context, "limit", 256, cast=int))
    parsed = parser.parse_args(normalize_except_args(args))
    target_args = commandlet.values_or_var(context, parsed.targets, "targets", required=True)
    targets = exclude_hosts(expand_targets(target_args, parsed.limit), parsed.except_)
    options: list[str] = [f"--arguments={parsed.arguments}", f"--limit={parsed.limit}"]
    if parsed.silent:
        options.append("--silent")
    if parsed.except_:
        options.extend(["--except", parsed.except_])
    return HostScannerIntent(targets, parsed.arguments, tuple(options))


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


def network_policy(context: CommandContext) -> tuple[tuple[Any, ...], tuple[Any, ...], str]:
    """Return allowed networks, denied networks, and policy mode."""
    allowed = tuple(parse_networks(context.vars.get_global("policy.network.allow", "") or ""))
    denied = tuple(parse_networks(context.vars.get_global("policy.network.deny", "169.254.169.254/32") or "169.254.169.254/32"))
    mode = context.vars.get_global("policy.network.mode", "warn") or "warn"
    return allowed, denied, mode


def parse_networks(value: str) -> tuple[Any, ...]:
    """Parse comma/space separated network policy values."""
    networks = []
    for item in split_var_values(value):
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            for host in host_candidates(item):
                networks.append(ipaddress.ip_network(host, strict=False))
    return tuple(networks)


def apply_network_policy(
    targets: Iterable[str],
    allowed: tuple[Any, ...],
    denied: tuple[Any, ...],
) -> tuple[tuple[str, ...], list[str]]:
    """Return allowed target strings and policy warnings."""
    kept: list[str] = []
    warnings: list[str] = []
    for target in targets:
        address = ipaddress.ip_address(target)
        if any(address in network for network in denied):
            warnings.append(f"{target} is denied by network policy")
            continue
        if allowed and not any(address in network for network in allowed):
            warnings.append(f"{target} is outside allowed network scope")
            continue
        kept.append(target)
    return tuple(kept), warnings


def plan_required(context: CommandContext) -> bool:
    """Return global policy for requiring plan approval."""
    return parse_bool(context.vars.get_global("plan.required", "false") or "false")


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HostScanner()
