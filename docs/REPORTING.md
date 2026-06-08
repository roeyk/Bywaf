# Reporting

`report` is the operator-facing finding inbox. It renders normalized finding
events as grouped, reviewable rows so an operator can see what needs attention
without manually querying raw event topics.

Reports are views over existing project data. They do not copy or own finding
payloads, raw facts, artifacts, notes, or audit history.

By default, `report` also runs the standard safe passive synthesis bundle over
already-collected facts in the selected scope before rendering. This can turn
facts such as web fingerprints or service banners into reviewable indicator
findings without starting probes, confirming vulnerabilities, or broadening scan
scope. Use `analyze=off` when you want a pure snapshot of findings that already
exist.

## Contents

- [What Becomes Reportable](#what-becomes-reportable)
- [Default View](#default-view)
- [Network View](#network-view)
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
- `finding.confirmed`
- `finding.new`
- `finding.updated`
- `finding.merge_candidate`

Finding payloads should be built with `bywaf.finding.candidate_payload(...)`
or `bywaf.finding.confirmed_payload(...)`.
The reporting layer expects normalized fields such as `finding_id`, `class`,
`severity`, `confidence`, `target_scope`, `target`, `identifiers`, `affected`,
`evidence`, and `sources`.

For normal render actions, `report` can synthesize passive findings from
selected context facts before it renders. The initial synthesis bundle reuses
the technology-indicator analyzer, deduplicates only the fresh candidates, and
keeps the result as candidate evidence. Review actions such as `report accept`
and `report reject` operate on already selected rows and do not run synthesis.
When visible findings include `confidence_basis`, compact report tables include
a `Basis` column and detail views include `Confidence basis`. Values such as
`version indicator` and `fingerprint indicator` explain why a candidate exists;
they do not make the finding confirmed.

## Default View

Run `report` with no selector during field work:

```text
bywaf> report
bywaf> report analyze=off
```

The default view chooses the latest scope that produced finding events, usually
the latest pipeline first, then job or step context when that is the only
available scope. It shows a count summary before listing rows:

```text
Findings: 12 total
Review: 3 accepted, 2 confirmed, 1 deferred, 0 rejected, 6 unreviewed

Open findings:
Findings
#  Finding                               Affected                      CVE      Severity  Review
1  Exposed Git repository configuration  https://example/.git/config   CWE-538  high      unreviewed

Use `report <#>` or `report detail <#>` for evidence, artifacts, and provenance.
```

When multiple events group into one logical finding, the compact inbox
summarizes the affected resources represented by the group. For example, a
web-origin finding observed on two URLs can render as `2 affected:
https://example/.git/config; https://example/app/.git/config` in the
`Affected` column, while `report <#>` shows the full affected/evidence/source
detail.

By default, `report` shows open findings: unreviewed findings plus confirmed
findings that should stay visible during field work. Use `status=all`,
`status=accepted`, `status=confirmed`, `status=deferred`, `status=rejected`, or
`status=unreviewed` to inspect a specific review state.

Use `cve=` to filter findings by CVE identifier:

```text
bywaf> report cve=CVE-2021-41773
bywaf> report cve=CVE-2021-41773,CVE-2021-42013
bywaf> report cve=CVE-2021-*
```

The selector matches CVEs present in finding `identifiers`. `*` is supported
for wildcard matching. A future advisory relationship provider may support the
reserved `CVE-...+` related-CVE form; until then, use explicit comma-separated
lists or wildcard selectors.

Use ordering flags when a review pass needs a specific queue shape:

```text
bywaf> report status=all --accepted-first
bywaf> report status=all --candidates-first
```

`--accepted-first` moves findings with the latest `accepted` review marker to
the top of the current report view. `--candidates-first` moves candidate or
potential findings ahead of confirmed rows.

## Network View

Use `report network` when you want the current host-centric picture instead of
the finding inbox:

```text
bywaf> report network
bywaf> report network pipeline=1
```

This view summarizes shared facts such as `host.found`, `name.resolved`,
`port.open`, `http.endpoint`, and finding titles by host. It is the report-side
counterpart to task-specific views such as `ports`: use `ports` for a compact
portscanner result, and use `report network` when you want those observations
placed into the broader assessment picture.

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
  Inspect artifacts with: artifact list step=...
  Provenance: events=42; pipeline=...; step=...
  Latest update: 2026-05-27T12:00:00+00:00
```

Detail views and table/export rows prefer the normalized `affected` list when
it is present, and fall back to the primary `target` only when a finding has no
affected-resource entries. This keeps canonical `finding.new` output from
`finding_dedupe` readable when one grouped finding represents multiple URLs,
paths, or service instances.

Report detail intentionally references artifact rows instead of embedding file
bodies. Use the printed `artifact list ...` command to browse the evidence set,
or `artifact show <id>` to inspect one artifact's provenance, hash, and export
commands. If a finding has artifacts from multiple producer steps, report detail
also groups those references by producing commandlet/scope.

## Scoped Views

Use selectors when you know the work scope:

```text
bywaf> report pipeline=1
bywaf> report pipeline=1,2,3
bywaf> report job=7
bywaf> report step=12
bywaf> report status=all pipeline=1
bywaf> report status=all pipeline=1 --accepted-first
bywaf> report status=all pipeline=1 --candidates-first
```

Save a named report scope when you expect to revisit the same set of work:

```text
bywaf> report create name=client-a pipeline=1,2,3
bywaf> report show name=client-a
bywaf> report update name=client-a pipeline=1,2,3,4
```

Saved scopes are append-only events over selectors. They do not copy findings
or artifact bodies into a separate report store. `report update` appends a new
scope event for the same name, and `report show` uses the latest saved scope.

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

Review commands use the `finding.review` capability and write
`finding.reviewed` events. They do not mutate the original finding payload.

```text
bywaf> report accept all pipeline=1
bywaf> report confirm 1 pipeline=1 note=validated manually
bywaf> report accept 1-3,7-9 pipeline=1 note=validated during retest
bywaf> report defer 4 pipeline=1 note=needs owner confirmation
bywaf> report reject 2 pipeline=1 note=false positive after manual check
bywaf> finding confirm 1 pipeline=1
bywaf> finding confirm all cve=CVE-2021-* pipeline=1
bywaf> finding unconfirm 1 status=confirmed pipeline=1
```

Selection values are row numbers from the current report view:

- `all`
- `1`
- `1-4`
- comma-separated mixes such as `1-3,7,9-11`

Use `note=` for operator context. Put `note=` last when the note contains
spaces.

`finding.confirmed` is proof produced by a plugin. `finding confirm ...` and
`report confirm ...` are operator review decisions. Both make a row show as
confirmed in reports, but the event history preserves which one happened.

## Current Boundaries

The current `report` command is an interactive inbox, scoped renderer, review
tool, and saved-scope manager. Saved scopes are intentionally lightweight:
they name selector sets and current render preferences over canonical events.
They are not report-owned finding stores.

Planned follow-up work includes:

- richer report templates
- export formats for delivery
- "what changed since I last looked" resume/status summaries

Reports should continue to remain views over canonical event and artifact data.
