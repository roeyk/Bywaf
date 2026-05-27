# Reporting

`report` is the operator-facing finding inbox. It renders normalized finding
events as grouped, reviewable rows so an operator can see what needs attention
without manually querying raw event topics.

Reports are views over existing project data. They do not copy or own finding
payloads, raw facts, artifacts, notes, or audit history.

## Contents

- [What Becomes Reportable](#what-becomes-reportable)
- [Default View](#default-view)
- [Finding Detail](#finding-detail)
- [Scoped Views](#scoped-views)
- [Grouping Behavior](#grouping-behavior)
- [Review State](#review-state)
- [Current Boundaries](#current-boundaries)

## What Becomes Reportable

A commandlet can emit many kinds of fact events, such as `port.open`,
`http.endpoint`, or tool-specific scanner rows. A fact becomes reportable when a
plugin or analysis commandlet emits a normalized finding topic:

- `finding.candidate`
- `finding.new`
- `finding.updated`
- `finding.merge_candidate`

Finding payloads should be built with `bywaf.finding.candidate_payload(...)`.
The reporting layer expects normalized fields such as `finding_id`, `class`,
`severity`, `confidence`, `target_scope`, `target`, `identifiers`, `affected`,
`evidence`, and `sources`.

## Default View

Run `report` with no selector during field work:

```text
bywaf> report
```

The default view chooses the latest scope that produced finding events, usually
the latest pipeline first, then job or step context when that is the only
available scope. It shows a count summary before listing rows:

```text
Findings: 12 total, 3 accepted, 1 deferred, 0 rejected, 8 unreviewed

Unreviewed findings:
Findings
#  Finding                               Affected                      CVE      Severity
1  Exposed Git repository configuration  https://example/.git/config   CWE-538  high

Use `report <#>` or `report detail <#>` for evidence, artifacts, and provenance.
```

By default, `report` shows unreviewed findings. Use `status=all`,
`status=accepted`, `status=deferred`, or `status=rejected` to inspect other
review states.

## Finding Detail

Use a row number from the current report view to drill into the finding:

```text
bywaf> report 1
bywaf> report detail 1-3
bywaf> report detail 1 pipeline=7
```

The detail view keeps the same scope and status selectors, then adds evidence,
affected resources, sources, artifacts, provenance, and latest update time:

```text
Details
1. Exposed Git repository configuration
  Affected: https://example/.git/config
  Evidence: /.git/config returned Git configuration content
  Sources: git_expose_check:repo.git_config.checked
  Artifacts: #3 proof.txt text/plain size=12 artifact-proof
  Provenance: events=42; pipeline=...; step=...
  Latest update: 2026-05-27T12:00:00+00:00
```

## Scoped Views

Use selectors when you know the work scope:

```text
bywaf> report pipeline=1
bywaf> report pipeline=1,2,3
bywaf> report job=7
bywaf> report step=12
bywaf> report status=all pipeline=1
```

Selector values use the same include/exclude grammar as event inspection:
comma-separated values are ORed, `!value` excludes values, and different
selector keys are ANDed together. Host/event selectors also accept CIDR and
compact IPv4 last-octet ranges, for example
`host=192.168.50.0/24,!192.168.50.1-128`.

Use the selector that matches the question:

| Selector | Use when |
| --- | --- |
| `pipeline=` | You want findings from a whole command chain or attached workflow. |
| `job=` | You want findings produced by one foreground/background execution lifecycle. |
| `step=` | You want findings from one commandlet invocation inside a pipeline. |

## Grouping Behavior

Reporting groups mechanically; plugins provide the semantic hints.

The grouping order is:

1. explicit `group_key`
2. derived `class + target_scope + strongest identifier`
3. derived `class + target_scope`
4. `finding_id`
5. event id fallback

Plugins should choose `target_scope` according to what the vulnerability affects:

| Scope | Typical meaning |
| --- | --- |
| `host` | Host-wide issue. |
| `host_port` | Host/port issue without deeper service identity. |
| `service` | One network service. |
| `web_origin` | One scheme/host/port web origin. |
| `web_app` | One application under an origin. |
| `web_route` | One route, path, or endpoint. |
| `cloud_resource` | One cloud resource. |

Example: if the same CVE appears on `/`, `/admin`, and `/login`, but the plugin
knows the vulnerable component is origin-wide, it should emit the same
`target_scope` and CVE for every observation and put each URL in `affected`.
`report` will render one grouped finding with multiple affected locations.

If the issue is truly route-specific, the plugin should use `web_route` so
those paths split into separate report rows.

## Review State

Review commands write `finding.reviewed` events. They do not mutate the
original finding payload.

```text
bywaf> report accept all pipeline=1
bywaf> report accept 1-3,7-9 pipeline=1 note=validated during retest
bywaf> report defer 4 pipeline=1 note=needs owner confirmation
bywaf> report reject 2 pipeline=1 note=false positive after manual check
```

Selection values are row numbers from the current report view:

- `all`
- `1`
- `1-4`
- comma-separated mixes such as `1-3,7,9-11`

Use `note=` for operator context. Put `note=` last when the note contains
spaces.

## Current Boundaries

The current `report` command is an interactive inbox and scoped renderer. It is
not yet a durable report-object manager.

Planned follow-up work includes:

- `report create/update/show/export`
- saved report scopes
- richer report templates
- export formats for delivery
- "what changed since I last looked" resume/status summaries

Until then, reports should remain views over canonical event and artifact data.
