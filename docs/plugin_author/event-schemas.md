# Shared Event Schemas

Shared event schemas are Bywaf's normalized result vocabulary. They let one
plugin publish a fact and another plugin, view, report, or bundle consume it
without knowing the original scanner.

## Contents

- [When To Use A Schema](#when-to-use-a-schema)
- [Why Schemas Instead Of Plugin Classes](#why-schemas-instead-of-plugin-classes)
- [Deserialize At The Boundary](#deserialize-at-the-boundary)
- [Plugin-Owned Schemas](#plugin-owned-schemas)
- [Declare Consumes And Emits](#declare-consumes-and-emits)
- [Keep Raw Tool Detail Separate](#keep-raw-tool-detail-separate)
- [Examples](#examples)
- [Checking](#checking)

## When To Use A Schema

Use a shared schema when the data should be useful outside your plugin:

- `host.found`: a host is alive or reachable
- `name.resolved`: one hostname resolved to one concrete address
- `port.open`: a host exposes a network port
- `http.endpoint`: an HTTP or HTTPS endpoint is reachable
- `smb.share.found`: an SMB share exists on a host
- `finding.candidate`: a normalized security finding that should enter review
- `artifact.attached`: artifact metadata attached to provenance

Framework-known schemas live in `bywaf/event_schemas.py` and are summarized
in [Event Model](../EVENT_MODEL.md#shared-event-schemas). Plugin-private
topics are still allowed for scanner-specific detail.

## Why Schemas Instead Of Plugin Classes

Shared events are the durable interchange format, not the plugin's internal
domain model. For framework-known schemas, import the framework-provided
object class from `bywaf.event_schema_objects`. For plugin-private or experimental
schemas, define a local `EventSchemaObject` subclass.

That is intentional. It keeps the database and pipeline boundary stable while
letting plugin authors use clean local models inside their code. Downstream
plugins only depend on the shared schema fields, not on another plugin's
classes, helper functions, or scanner-specific structures.

## Deserialize At The Boundary

Plugin logic should not have to pass dictionaries around. For a framework-known
schema, import its object class and use `from_event(...)` when consuming a
shared event and `to_payload()` when publishing one.

```python
from bywaf.event_schema_objects import OpenPort


for event in input_events:
    if event.topic != "port.open":
        continue
    port = OpenPort.from_event(event)
    probe_service(port.host, port.port, port.protocol, port.service)
```

The base class validates the event against the shared schema and passes
matching schema fields into your constructor. Extra schema fields are ignored
unless your constructor accepts `**kwargs`, so your local object only needs the
fields your plugin actually uses.

When publishing a shared event, serialize the object back to the schema fields
at the edge:

```python
context.events.publish(OpenPort.__topic__, port.to_payload())
```

That keeps the database representation simple and stable while keeping plugin
implementation code typed and readable.

Framework-provided schema object classes currently live in `bywaf.event_schema_objects`:

- `HostFound`
- `NameResolved`
- `OpenPort`
- `HttpEndpoint`
- `SmbShareFound`
- `ArtifactAttached`

Use `EventSchemaObject` directly only when a plugin owns a private topic or is
prototyping a candidate schema before it becomes part of the framework
vocabulary.

## Plugin-Owned Schemas

If a plugin introduces a fact that the framework does not know yet, the plugin
can still offer object-oriented interoperability to other plugins by exporting
its own schema object class.

```python
# smb_enum/event_schema_objects.py
from dataclasses import dataclass

from bywaf.event_schemas import EventSchemaObject


@dataclass(frozen=True)
class SmbSession(EventSchemaObject):
    __topic__ = "smb.session.observed"

    host: str
    username: str
    domain: str = ""
```

The producing plugin publishes the serialized boundary form:

```python
session = SmbSession(host="dc01.example.test", username="alice", domain="EXAMPLE")
context.events.publish(SmbSession.__topic__, session.to_payload())
```

A consuming plugin imports the plugin-owned class and immediately returns to
typed code:

```python
from smb_enum.event_schema_objects import SmbSession


for event in input_events:
    if event.topic == SmbSession.__topic__:
        session = SmbSession.from_event(event)
        inspect_session(session.host, session.username, session.domain)
```

Declare the topic in `consumes` and `emits` as usual. Framework tooling can see
the event flow from the manifest, while plugins that opt into the producer's
Python package can use the exported object class. If the topic becomes broadly
useful, promote it into a framework-known schema and move the canonical class
into `bywaf.event_schema_objects`.

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

Shared schemas should be stable and portable. If a scanner produces extra
details that do not fit a shared schema, keep that detail in a plugin-private
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
