"""SMB probing commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Checks SMB endpoints and emits service or finding events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugin import kv_to_args
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"domain": "", "password": "", "port": "445", "timeout": "5", "username": ""}
OPTION_KEYS = {"domain", "password", "port", "timeout", "username"}


@commandlet(
    name="smb_probe",
    description="Probe SMB server metadata with Impacket.",
    usage="smb_probe [username=USER password=PASS domain=DOMAIN] <host ...>",
    examples=("smb_probe 127.0.0.1", "smb_probe domain=EXAMPLE username=user password=secret dc.example.test"),
)
@option("domain", "SMB domain")
@option("password", "SMB password", secret=True)
@option("port", "SMB port", "445")
@option("timeout", "connection timeout seconds", "5")
@option("username", "SMB username")
class SmbProbe(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Connect to SMB and publish server metadata."""
        del input_events
        parser = self.parser()
        parser.add_argument("hosts", nargs="+")
        parser.add_argument("--domain", default=self.var_default(context, "domain", ""))
        parser.add_argument("--password", default=self.var_default(context, "password", ""))
        parser.add_argument("--port", type=int, default=self.var_default(context, "port", 445, cast=int))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parser.add_argument("--username", default=self.var_default(context, "username", ""))
        parsed = parser.parse_args(kv_to_args(args, OPTION_KEYS))
        password = context.secrets.resolve(parsed.password, "")
        smb_mod = optional_module(context, "impacket.smbconnection", "impacket")
        if smb_mod is None:
            return ()
        for host in parsed.hosts:
            # Each host is independent. Publish partial metadata even when a
            # later host fails so long sweeps still leave useful evidence.
            context.audit_capability("network.connect")
            try:
                conn = smb_mod.SMBConnection(host, host, sess_port=parsed.port, timeout=parsed.timeout)
            except Exception as exc:
                publish_smb_error(context, host, parsed.port, exc)
                continue
            try:
                try:
                    if parsed.username or password:
                        conn.login(parsed.username, password, parsed.domain)
                except Exception as exc:
                    publish_smb_error(context, host, parsed.port, exc)
                    continue
                publish_smb_server(context, conn, host, parsed.port)
            finally:
                conn.close()
        return ()


def publish_smb_server(context: CommandContext, conn, host: str, port: int) -> None:
    """Publish SMB server metadata from one established connection."""
    context.events.publish(
        "smb.server",
        {
            "host": host,
            "port": port,
            "server_name": safe_call(conn, "getServerName"),
            "server_domain": safe_call(conn, "getServerDomain"),
            "server_os": safe_call(conn, "getServerOS"),
            "shares": safe_shares(conn),
        },
    )


def publish_smb_error(context: CommandContext, host: str, port: int, exc: Exception) -> None:
    """Publish one SMB probe failure as service-scoped data."""
    context.events.publish("smb.server", {"host": host, "port": port, "error": str(exc)})


def safe_call(obj, method: str) -> str:
    """Call an optional Impacket metadata method."""
    try:
        return str(getattr(obj, method)())
    except Exception:
        # SMB servers frequently restrict anonymous metadata. Treat that as
        # absent metadata, not as a failed probe.
        return ""


def safe_shares(conn) -> list[str]:
    """Return share names when listing is allowed."""
    try:
        return [str(share["shi1_netname"]).rstrip("\x00") for share in conn.listShares()]
    except Exception:
        # Share enumeration is often blocked even when the service is alive.
        return []


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return SmbProbe()
