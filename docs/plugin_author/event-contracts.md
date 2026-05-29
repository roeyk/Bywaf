# Shared Event Contracts

Shared event contracts are Bywaf's normalized result vocabulary. They let one
plugin publish a fact and another plugin, view, report, or bundle consume it
without knowing the original scanner.

## Contents

- [When To Use A Contract](#when-to-use-a-contract)
- [Why Contracts Instead Of Shared Classes](#why-contracts-instead-of-shared-classes)
- [Deserialize At The Boundary](#deserialize-at-the-boundary)
- [Declare Consumes And Emits](#declare-consumes-and-emits)
- [Keep Raw Tool Detail Separate](#keep-raw-tool-detail-separate)
- [Examples](#examples)
- [Checking](#checking)

## When To Use A Contract

Use a shared contract when the data should be useful outside your plugin:

- `host.found`: a host is alive or reachable
- `name.resolved`: one hostname resolved to one concrete address
- `port.open`: a host exposes a network port
- `http.endpoint`: an HTTP or HTTPS endpoint is reachable
- `smb.share.found`: an SMB share exists on a host
- `finding.candidate`: a normalized security finding that should enter review
- `artifact.attached`: artifact metadata attached to provenance

Framework-known contracts live in `bywaf/event_contracts.py` and are summarized
in [Event Model](../EVENT_MODEL.md#shared-event-contracts). Plugin-private
topics are still allowed for scanner-specific detail.

## Why Contracts Instead Of Shared Classes

Shared events are the durable interchange format, not the plugin's internal
domain model. A plugin can consume `port.open`, `http.endpoint`, or
`smb.share.found` and immediately convert the payload into its own typed object
for parsing, probing, correlation, or reporting logic.

That is intentional. It keeps the database and pipeline boundary stable while
letting plugin authors use clean local models inside their code. Downstream
plugins only depend on the shared contract fields, not on another plugin's
classes, helper functions, or scanner-specific structures.

## Deserialize At The Boundary

Plugin logic should not have to pass dictionaries around. Use
`contract_object(...)` when consuming a shared event, then work with your own
dataclass or domain object internally.

```python
from dataclasses import dataclass

from bywaf.event_contracts import contract_object


@dataclass(frozen=True)
class OpenPort:
    host: str
    port: int
    protocol: str
    service: str = ""


for event in input_events:
    if event.topic != "port.open":
        continue
    port = contract_object(event, "port.open", OpenPort)
    probe_service(port.host, port.port, port.protocol, port.service)
```

The helper validates the event against the shared contract and passes matching
contract fields into your constructor. Extra contract fields are ignored unless
your factory accepts `**kwargs`, so your local object only needs the fields your
plugin actually uses.

When publishing a shared event, serialize back to the contract fields at the
edge:

```python
context.events.publish(
    "port.open",
    {
        "host": port.host,
        "port": port.port,
        "protocol": port.protocol,
        "service": port.service,
    },
)
```

That keeps the database representation simple and stable while keeping plugin
implementation code typed and readable.

## Declare Consumes And Emits

Declare shared inputs and outputs in both Python metadata and the sidecar
manifest.

```python
@commandlet(
    name="smb_shares",
    consumes=("host.found",),
    emits=("smb.share.found", "finding.candidate"),
    capabilities=("network.connect", "db.write:finding.candidate"),
)
class SmbShares(CommandletBase):
    ...
```

```toml
[[commandlets]]
name = "smb_shares"
consumes = ["host.found"]
emits = ["smb.share.found", "finding.candidate"]
capabilities = [
  "network.connect",
  "db.write:finding.candidate",
]
```

The manifest is intentionally redundant: it lets packaging and review tools
inspect a plugin without importing its code.

## Keep Raw Tool Detail Separate

Shared contracts should be stable and portable. If a scanner produces extra
details that do not fit a shared contract, keep that detail in a plugin-private
topic or artifact, then publish the normalized fact separately.

```text
smb_enum.raw_share_acl  scanner-specific ACL and banner detail
smb.share.found        normalized share fact
finding.candidate      reportable risky condition, if one exists
```

This lets `results`, `report`, future GUI views, and follow-up plugins work from
the normalized facts while the raw detail remains available for evidence.

## Examples

One hostname with multiple addresses should be multiple `name.resolved` facts:

```python
for address in addresses:
    context.events.publish(
        "name.resolved",
        {"name": "www.example.test", "host": address, "resolver": "system"},
    )
```

An SMB enumeration plugin can consume discovered hosts and publish shares:

```python
for event in input_events:
    if event.topic != "host.found":
        continue
    host = event.payload["host"]
    for share in enumerate_shares(host):
        context.events.publish(
            "smb.share.found",
            {
                "host": host,
                "share": share.name,
                "port": 445,
                "protocol": "smb",
                "access": share.access,
                "authenticated": share.authenticated,
            },
        )
```

If a share is risky, also publish a finding candidate with the standard helper.

## Checking

Run the checker before loading or packaging a plugin:

```bash
python3 scripts/plugin_check.py path/to/plugin --strict-inference
```

The checker validates declared shared-topic emits and catches simple literal
payload mistakes, including assigned literal payloads passed to
`context.events.publish(...)`.
