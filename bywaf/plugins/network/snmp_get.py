"""SNMP GET commandlet backed by pysnmp."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"community": "public", "oid": "1.3.6.1.2.1.1.1.0", "port": "161", "timeout": "5"}
OPTION_KEYS = {"community", "oid", "port", "timeout"}


@commandlet(
    name="snmp_get",
    description="Read one SNMP OID with pysnmp.",
    usage="snmp_get [community=public] [oid=OID] <host ...>",
    examples=("snmp_get 127.0.0.1", "snmp_get oid=1.3.6.1.2.1.1.5.0 127.0.0.1"),
    emits=("snmp.value",),
    capabilities=("db.write:snmp.value", "db.write:tool.error", "network.connect"),
)
@option("community", "SNMP community", "public")
@option("oid", "SNMP OID", "1.3.6.1.2.1.1.1.0")
@option("port", "SNMP UDP port", "161")
@option("timeout", "timeout seconds", "5")
class SnmpGet(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Read one OID from one or more hosts."""
        del input_events
        parser = self.parser()
        parser.add_argument("hosts", nargs="+")
        parser.add_argument("--community", default=self.var_default(context, "community", "public"))
        parser.add_argument("--oid", default=self.var_default(context, "oid", "1.3.6.1.2.1.1.1.0"))
        parser.add_argument("--port", type=int, default=self.var_default(context, "port", 161, cast=int))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        hlapi = optional_module(context, "pysnmp.hlapi", "pysnmp")
        if hlapi is None:
            return ()
        for host in parsed.hosts:
            context.audit_capability("network.connect")
            publish_snmp_value(context, hlapi, host, parsed.port, parsed.community, parsed.oid, parsed.timeout)
        return ()


def publish_snmp_value(context: CommandContext, hlapi: Any, host: str, port: int, community: str, oid: str, timeout: float) -> None:
    """Run one pysnmp GET and publish the result."""
    iterator = hlapi.getCmd(
        hlapi.SnmpEngine(),
        hlapi.CommunityData(community),
        hlapi.UdpTransportTarget((host, port), timeout=timeout, retries=0),
        hlapi.ContextData(),
        hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
    )
    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication:
        context.events.publish("snmp.value", {"host": host, "port": port, "oid": oid, "error": str(error_indication)})
        return
    if error_status:
        context.events.publish("snmp.value", {"host": host, "port": port, "oid": oid, "error": str(error_status), "error_index": int(error_index)})
        return
    for name, value in var_binds:
        context.events.publish("snmp.value", {"host": host, "port": port, "oid": str(name), "value": str(value)})


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return SnmpGet()
