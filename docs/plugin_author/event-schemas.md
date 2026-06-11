# Shared Event Schemas

Shared event schemas are Bywaf's normalized result vocabulary. They let one
plugin publish a fact and another plugin, view, report, or bundle consume it
without knowing the original scanner.

## Contents

- [When To Use A Schema](#when-to-use-a-schema)
- [Why Schemas Instead Of Plugin Classes](#why-schemas-instead-of-plugin-classes)
- [Deserialize At The Boundary](#deserialize-at-the-boundary)
- [Plugin-Owned Schemas](#plugin-owned-schemas)
- [Schema Dependencies And Plugin Dependencies](#schema-dependencies-and-plugin-dependencies)
- [Inspect Registered Schemas](#inspect-registered-schemas)
- [Declare Consumes And Emits](#declare-consumes-and-emits)
- [Keep Raw Tool Detail Separate](#keep-raw-tool-detail-separate)
- [High-Volume Event Emission](#high-volume-event-emission)
- [Examples](#examples)
- [Checking](#checking)

## When To Use A Schema

Use a shared schema when the data should be useful outside your plugin:

- `host.found`: a host is alive or reachable
- `name.resolved`: one hostname resolved to one concrete address
- `port.open`: a host exposes a network port
- `http.endpoint`: an HTTP or HTTPS endpoint is reachable
- `web.screenshotted_host`: one host or endpoint has screenshot artifacts
- `tcp.banner`: a TCP service banner or first response was captured
- `network.route.hop`: one hop observed while tracing a route
- `smb.share.found`: an SMB share exists on a host
- `finding.candidate`: a normalized security finding that should enter review
- `artifact.attached`: artifact metadata attached to provenance

Framework-known schemas live in `bywaf/event/schemas.py` and are summarized
in [Event Model](../EVENT_MODEL.md#shared-event-schemas). Plugin-owned schemas
are declared in the plugin manifest so Bywaf can validate their event payloads
without importing plugin code. Plugin-private topics are still allowed for
scanner-specific detail.

For finding candidates, emit both a confidence label and, when known, a
`confidence_basis` such as `safe_probe`, `content_indicator`,
`service_indicator`, `fingerprint_indicator`, `version_indicator`, or
`port_indicator`. This keeps CVE- or version-adjacent checks honest: a version
or fingerprint match should remain a candidate with an explicit indicator basis
unless the plugin also performs a documented safe confirmation probe.

## Why Schemas Instead Of Plugin Classes

Shared events are the durable interchange format, not the plugin's internal
domain model. For framework-known schemas, import the framework-provided
object class from `bywaf.event.schema_objects`. For plugin-private or experimental
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
from bywaf.event.schema_objects import OpenPort


for event in input_events:
    if event.topic != "port.open":
        continue
    port = OpenPort.from_event(event)
    probe_service(port.host, port.port, port.protocol, port.service)
```

For a batch of input events, use the class helper to pull out only matching
schema objects:

```python
for port in OpenPort.from_events(input_events):
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

The command context also exposes a shorthand that keeps the topic and payload
serialization together:

```python
context.events.publish_object(port)
```

That keeps the database representation simple and stable while keeping plugin
implementation code typed and readable.

Framework-provided schema object classes currently live in `bywaf.event.schema_objects`:

- `HostFound`
- `NameResolved`
- `OpenPort`
- `HttpEndpoint`
- `ScreenshottedHost`
- `TcpBanner`
- `NetworkRouteHop`
- `SmbShareFound`
- `ArtifactAttached`

Use `EventSchemaObject` directly only when a plugin owns a private topic or is
prototyping a candidate schema before it becomes part of the framework
vocabulary.

## Plugin-Owned Schemas

If a plugin introduces a fact that the framework does not know yet, declare the
schema in `bywaf.plugin.toml`. That makes the topic visible to `plugin_check`,
runtime validation, `results`, and future inventory/report views without
requiring other plugins to import this plugin's Python classes.

The manifest declaration is the authority for plugin-owned schema metadata.
Keep it data-only: Bywaf must be able to inspect schemas, capabilities,
consumes/emits, and versions before executing plugin Python. Plugin code may
define local `EventSchemaObject` convenience classes, but those classes do not
register interoperability metadata by themselves.

An `[[event_schemas]]` entry registers the topic as a schema-backed topic. The
commandlet must still list the topic in `emits`, so Bywaf can distinguish “this
provider owns the shape of this event” from “this commandlet actually produces
this event.” Schema-backed events published through `context.events.publish(...)`
or `context.events.publish_object(...)` are validated before insertion. The
default is strict; during development, operators can explicitly set
`global.schema.validation=off` to allow invalid schema-backed payloads while
debugging.

```toml
[[event_schemas]]
topic = "smb.session.observed"
version = "1"
summary = "An authenticated SMB session was observed."

[[event_schemas.fields]]
name = "host"
type = "str"
required = true
description = "SMB server host."

[[event_schemas.fields]]
name = "username"
type = "str"
required = true

[[event_schemas.fields]]
name = "domain"
type = "str"
```

The `version` value is the producer/consumer interoperability marker. Start at
`"1"` and bump it when a field's meaning, required status, or allowed values
change in a way that an older consumer might misread.

The producing plugin can still keep an object-oriented local model:

```python
# smb_enum/event_schema_objects.py
from dataclasses import dataclass

from bywaf.event.schemas import EventSchemaObject


@dataclass(frozen=True)
class SmbSession(EventSchemaObject):
    __topic__ = "smb.session.observed"

    host: str
    username: str
    domain: str = ""
```

Then it publishes the serialized boundary form:

```python
session = SmbSession(host="dc01.example.test", username="alice", domain="EXAMPLE")
context.events.publish_object(session)
```

A consuming plugin should depend on the manifest-declared event schema, not on
the producer plugin's Python module. It can use `schema_payload(...)`, or define
its own local object for the same topic if that makes its implementation
cleaner:

```python
from dataclasses import dataclass

from bywaf.event.schemas import EventSchemaObject


@dataclass(frozen=True)
class SmbSession(EventSchemaObject):
    __topic__ = "smb.session.observed"

    host: str
    username: str
    domain: str = ""

for session in SmbSession.from_events(input_events):
    inspect_session(session.host, session.username, session.domain)
```

Declare the topic in `consumes` and `emits` as usual. If the topic becomes
broadly useful, promote it into a framework-known schema and move the canonical
class into `bywaf.event.schema_objects`. Promotion is a framework maintainer
decision, not a plugin-side registration action; see
[Framework Development](../FRAMEWORK_DEVELOPMENT.md#promote-a-plugin-owned-event-schema).

Promotion should normally keep the same topic name and version lineage so
existing producers and consumers keep interoperating. Create a new framework
topic only when the plugin-owned topic name or field meanings are clearly wrong.
Temporary aliases are a migration bridge, not the long-term model.

## Schema Dependencies And Plugin Dependencies

A topic is the event channel name, such as `http.endpoint`. A schema is the
data contract for events on that topic: required fields, optional fields,
version, and field meanings. A commandlet can declare that it consumes a topic
without requiring a specific producer plugin to be loaded.

`consumes = ["http.endpoint"]` means "this commandlet can use `http.endpoint`
events when they are supplied." It does not mean "load `http_probe`." Events
may come from an earlier pipeline step, stored project history, imported
evidence, a bundled plugin, or a third-party plugin that publishes the same
schema-backed contract.

Use schema dependencies for data contracts and plugin dependencies for exact
provider behavior:

```toml
[plugin]
requires_schemas = ["http.endpoint"]
requires_plugins = ["http.probe"]
```

Use `requires_schemas` when the plugin only needs a stable payload contract.
Use `requires_plugins` only when the plugin depends on something beyond a
schema, such as:

- a specific commandlet being available;
- artifacts produced by that plugin;
- side effects such as populating the database, starting a service, or
  refreshing runtime state;
- a long-running service, listener, exporter, watchdog, or external-tool
  wrapper;
- provider variables, defaults, profiles, or shared runtime settings;
- normalization behavior that is specific to that plugin, not just the event
  field names;
- external tool or library management that the other plugin owns.

Dependency checks are manifest-first. `plugin_check` scans manifests before
plugin import and reports missing required schemas, ambiguous plugin-owned
schema providers, and missing required plugins. Runtime auto-loading and
topological ordering of dependency closures remain future loader behavior.

## Inspect Registered Schemas

Use `schemas` in the REPL to inspect the active schema catalog loaded from the
framework and plugin manifests:

```text
schemas owner=plugin
schemas topic=web. sort=topic
schemas topic=web.fingerprint detail=true
```

The list view shows owner, topic, schema version, required fields, field count,
declared users, and summary. `detail=true` expands the field table and notes for
the selected schemas. This gives plugin authors a stable way to see what a
producer emits without importing that producer's Python module.

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

## High-Volume Event Emission

High-volume plugins should publish normalized facts through
`context.events.publish(...)` or `context.events.publish_object(...)`, not raw
database handles. The mediated event API adds provenance, schema validation,
and capability audit records while keeping the storage path consistent with the
rest of Bywaf.

Commandlets must declare the topics they may publish in `emits`. Runtime
contexts built by the runner enforce that `context.events.publish(...)` uses a
declared topic; publishing an undeclared topic fails by default. Schema
resolution remains runtime-based: if the topic has a registered schema, Bywaf
validates the payload before insertion. If a declared topic has no registered
schema, Bywaf records a topic-policy event and allows it by default unless the
operator changes `global.topic.unregistered.mode`.

For scanners that may emit thousands of results, prefer one durable event per
operator-meaningful fact. For example, a port scanner should publish one
`port.open` event per open port and use progress events around scan phases,
instead of writing every packet, retry, socket attempt, or parser-internal
state transition into the shared event log.

Before introducing a plugin that can emit very large result volumes, run the
maintainer benchmark in [Performance Benchmarks](../PERFORMANCE.md#sqlite-contention)
with `--workload plugin`. That workload publishes schema-valid `port.open`
events through the plugin-facing event API from multiple writer processes, so
it is the relevant storage check for high-volume native plugins.

## Examples

One hostname with multiple addresses should be multiple `name.resolved` facts:

```python
from bywaf.event.schema_objects import NameResolved


for address in addresses:
    context.events.publish_object(NameResolved("www.example.test", address, resolver="system"))
```

Route tracing should publish one `network.route.hop` fact per target and hop:

```python
from bywaf.event.schema_objects import NetworkRouteHop


hop = NetworkRouteHop(
    target="example.test",
    hop=1,
    host="router.local",
    ip="192.0.2.1",
    rtt_ms=1.2,
    status="responded",
    scanner="traceroute",
)
context.events.publish_object(hop)
```

An SMB enumeration plugin can consume discovered hosts and publish shares:

```python
from bywaf.event.schema_objects import HostFound, SmbShareFound


for event in input_events:
    if event.topic != "host.found":
        continue
    host = HostFound.from_event(event).host
    for share in enumerate_shares(host):
        context.events.publish_object(
            SmbShareFound(
                host,
                share.name,
                port=445,
                protocol="smb",
                access=share.access,
                authenticated=share.authenticated,
            )
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
