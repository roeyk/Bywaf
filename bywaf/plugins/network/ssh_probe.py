"""SSH probing commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Checks SSH endpoints and emits service metadata or findings.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.recon.dns_lookup import optional_module
from bywaf.plugins.target_policy import filter_host_port_targets

DEFAULTS = {"password": "", "port": "22", "timeout": "5", "username": ""}
OPTION_KEYS = {"password", "port", "timeout", "username"}


@commandlet(
    name="ssh_probe",
    description="Probe SSH service metadata with Paramiko.",
    usage="ssh_probe [port=22] [username=USER password=PASS] <host ...>",
    examples=("ssh_probe 127.0.0.1", "ssh_probe username=test password=test 127.0.0.1"),
)
@option("password", "SSH password", secret=True)
@option("port", "SSH port", "22")
@option("timeout", "connection timeout seconds", "5")
@option("username", "SSH username")
class SshProbe(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Probe SSH hosts from args or upstream port events."""
        parser = self.parser()
        parser.add_argument("hosts", nargs="*")
        parser.add_argument("--password", default=self.var_default(context, "password", ""))
        parser.add_argument("--port", type=int, default=self.var_default(context, "port", 22, cast=int))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parser.add_argument("--username", default=self.var_default(context, "username", ""))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        password = context.secrets.resolve(parsed.password, "")
        paramiko = optional_module(context, "paramiko", "paramiko")
        if paramiko is None:
            return ()
        for host, port in filter_host_port_targets(context, ssh_targets(parsed.hosts, parsed.port, input_events)):
            # Authentication success is not required for usefulness: failed
            # auth still confirms an SSH service and often yields a banner.
            context.audit_capability("network.connect")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=parsed.username or None,
                    password=password or None,
                    timeout=parsed.timeout,
                    banner_timeout=parsed.timeout,
                    auth_timeout=parsed.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                transport = client.get_transport()
                banner = getattr(transport, "remote_version", "") if transport is not None else ""
                context.events.publish("ssh.service", {"host": host, "port": port, "banner": banner, "auth": "success"})
            except Exception as exc:
                context.events.publish("ssh.service", {"host": host, "port": port, "error": str(exc), "auth": "failed"})
            finally:
                client.close()
        return ()


def ssh_targets(hosts: list[str], port: int, input_events: Iterable[Event]) -> list[tuple[str, int]]:
    """Resolve SSH targets from args or `port.open` events."""
    if hosts:
        return [(host, port) for host in hosts]
    # Pipeline mode narrows generic port.open input to the default SSH port.
    # Operators can still override with explicit host args and port= above.
    return [
        (str(event.payload["host"]), int(event.payload["port"]))
        for event in input_events
        if event.topic == "port.open" and int(event.payload.get("port", 0)) == 22
    ]


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return SshProbe()
