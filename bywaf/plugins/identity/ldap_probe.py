"""LDAP probing commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Checks LDAP endpoints and emits service or finding events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, kv_to_args, option
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"base-dn": "", "password": "", "port": "389", "ssl": "false", "timeout": "5", "username": ""}
OPTION_KEYS = {"base-dn", "password", "port", "ssl", "timeout", "username"}


@commandlet(
    name="ldap_probe",
    description="Probe LDAP bind and naming context metadata with ldap3.",
    usage="ldap_probe [username=USER password=PASS] <host>",
    examples=("ldap_probe dc.example.test", "ldap_probe username='EXAMPLE\\\\user' password=<secret-ref> dc.example.test"),
)
@option("base-dn", "optional LDAP search base")
@option("password", "LDAP password", secret=True)
@option("port", "LDAP port", "389")
@option("ssl", "use LDAPS", "false", ("true", "false"))
@option("timeout", "connection timeout seconds", "5")
@option("username", "LDAP username")
class LdapProbe(CommandletBase):
    """Commandlet that probes LDAP endpoints and emits directory service facts."""
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Bind to LDAP and publish server metadata."""
        del input_events
        parser = self.parser()
        parser.add_argument("host")
        parser.add_argument("--base-dn", default=self.var_default(context, "base-dn", ""))
        parser.add_argument("--password", default=self.var_default(context, "password", ""))
        parser.add_argument("--port", type=int, default=self.var_default(context, "port", 389, cast=int))
        parser.add_argument("--ssl", choices=("true", "false"), default=self.var_default(context, "ssl", "false"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parser.add_argument("--username", default=self.var_default(context, "username", ""))
        parsed = parser.parse_args(kv_to_args(args, OPTION_KEYS))
        password = context.secrets.resolve(parsed.password, "")
        ldap3 = optional_module(context, "ldap3", "ldap3")
        if ldap3 is None:
            return ()
        # Network and secret access are explicit capabilities: resolving the
        # password happens above, and the LDAP bind is the auditable network
        # action that follows.
        context.audit_capability("network.connect")
        server = ldap3.Server(parsed.host, port=parsed.port, use_ssl=parsed.ssl == "true", connect_timeout=parsed.timeout, get_info=ldap3.ALL)
        try:
            conn = ldap3.Connection(server, user=parsed.username or None, password=password or None, auto_bind=True)
        except Exception as exc:
            context.events.publish(
                "ldap.server",
                {"host": parsed.host, "port": parsed.port, "ssl": parsed.ssl == "true", "bound": False, "error": str(exc)},
            )
            return ()
        try:
            info = getattr(server, "info", None)
            # ldap3 exposes naming contexts via server.info after bind. Keep
            # the payload compact so downstream commandlets can treat it as
            # service metadata instead of a raw LDAP object.
            contexts = list(getattr(info, "naming_contexts", []) or [])
            context.events.publish("ldap.server", {"host": parsed.host, "port": parsed.port, "ssl": parsed.ssl == "true", "bound": bool(conn.bound), "naming_contexts": contexts})
        finally:
            conn.unbind()
        return ()


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return LdapProbe()
