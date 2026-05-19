"""SMB probe commandlet backed by Impacket."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"domain": "", "password": "", "port": "445", "timeout": "5", "username": ""}
OPTION_KEYS = {"domain", "password", "port", "timeout", "username"}


@commandlet(
    name="smb_probe",
    description="Probe SMB server metadata with Impacket.",
    usage="smb_probe [username=USER password=PASS domain=DOMAIN] <host ...>",
    examples=("smb_probe 127.0.0.1", "smb_probe domain=EXAMPLE username=user password=secret dc.example.test"),
    emits=("smb.server",),
    capabilities=("db.write:smb.server", "db.write:tool.error", "framework.secret.resolve", "network.connect"),
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
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        password = context.secrets.resolve(parsed.password, "")
        smb_mod = optional_module(context, "impacket.smbconnection", "impacket")
        if smb_mod is None:
            return ()
        for host in parsed.hosts:
            context.audit_capability("network.connect")
            conn = smb_mod.SMBConnection(host, host, sess_port=parsed.port, timeout=parsed.timeout)
            try:
                if parsed.username or password:
                    conn.login(parsed.username, password, parsed.domain)
                context.events.publish(
                    "smb.server",
                    {
                        "host": host,
                        "port": parsed.port,
                        "server_name": safe_call(conn, "getServerName"),
                        "server_domain": safe_call(conn, "getServerDomain"),
                        "server_os": safe_call(conn, "getServerOS"),
                        "shares": safe_shares(conn),
                    },
                )
            finally:
                conn.close()
        return ()


def safe_call(obj, method: str) -> str:
    """Call an optional Impacket metadata method."""
    try:
        return str(getattr(obj, method)())
    except Exception:
        return ""


def safe_shares(conn) -> list[str]:
    """Return share names when listing is allowed."""
    try:
        return [str(share["shi1_netname"]).rstrip("\x00") for share in conn.listShares()]
    except Exception:
        return []


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return SmbProbe()
