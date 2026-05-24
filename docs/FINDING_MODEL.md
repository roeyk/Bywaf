# Finding And Report Model

## Document Index

- [Purpose](#purpose)
- [Facts, Candidates, And Findings](#facts-candidates-and-findings)
- [Finding Payload](#finding-payload)
- [Finding Grouping](#finding-grouping)
- [Promotion And Deduplication](#promotion-and-deduplication)
- [Report Command](#report-command)
- [Current Boundaries](#current-boundaries)

## Purpose

Bywaf commandlets emit many low-level facts: open ports, HTTP endpoints, tool
warnings, screenshots, raw scanner rows, and tool errors. Operators should not
have to review every raw event when they want to answer "what did we find?"

The finding model separates those layers:

- Fact events describe observations.
- Finding events describe observations that may represent risk.
- Report commands render grouped findings for review or delivery.

Reports do not own raw findings. They are scoped views over event data and
artifact provenance already stored in the project.

## Facts, Candidates, And Findings

| Layer | Example topics | Meaning | Normal consumer |
| --- | --- | --- | --- |
| Fact | `port.open`, `http.endpoint`, `nikto.finding`, `web.screenshot` | Something a tool observed or produced | Follow-up commandlets, dedupe, report builders |
| Candidate | `finding.candidate`, `finding.new`, `finding.merge_candidate` | A normalized finding-shaped record that deserves review or correlation | `finding_dedupe`, `report`, `finding_report`, future triage commands |
| Confirmed finding | planned `finding.confirmed` | A finding accepted by a rule, commandlet, or operator as confirmed risk | Reports and exports |
| Review state | `finding.reviewed` | Operator or framework review marker for a finding id | `report new` and future triage flows |

An open port is usually a fact, not automatically a finding. A promoter rule
or commandlet can turn it into a finding candidate when the fact implies risk:
for example Telnet exposed to an unauthorized segment, unauthenticated admin
HTTP, or a CVE-specific confirmation signal.

## Finding Payload

The current normalized finding payload is intentionally small:

| Field | Meaning |
| --- | --- |
| `finding_id` | Stable id for the normalized finding. |
| `status` | Current state such as `new`, `updated`, or future review states. |
| `confidence` | Numeric confidence score when known. |
| `severity` | Severity label such as `info`, `low`, `medium`, `high`, or `critical`. |
| `class` | Finding class, vulnerability class, or scanner category. |
| `title` | Operator-facing finding title. |
| `finding_scope` | Semantic scope for grouping, such as `host`, `service`, `application`, `endpoint`, or `cloud_resource`. |
| `target` | Target identity, commonly host/port/path/scheme fields. |
| `identifiers` | CVE, CWE, GHSA, vendor IDs, or other stable identifiers. |
| `affected` | Specific affected locations or instances, such as URLs, paths, object names, or evidence references. |
| `group_key` | Optional plugin-provided grouping key when the plugin knows the semantic grouping better than the generic id hash. |
| `evidence` | Evidence snippets or references to artifact/event ids. |
| `sources` | Commandlets, tools, or topics that contributed evidence. |

Commandlets may emit richer fact payloads. The normalized finding layer keeps a
stable subset so reporting does not depend on every tool's native schema.

## Finding Grouping

Grouping answers: "which finding events represent the same logical finding?"

The detector or plugin is responsible for deciding the finding's semantic
scope. The framework should not guess whether a CVE is host-wide, service-wide,
application-wide, endpoint-specific, or cloud-resource-specific from a URL
alone. The plugin should encode that decision in `finding_scope`, `target`, and
optionally `group_key`.

Report grouping is intentionally mechanical:

1. Use `group_key` when present.
2. Otherwise use `finding_id`.
3. Otherwise fall back to the individual event id.

This keeps domain knowledge close to the detector while keeping the reporting
layer consistent.

Recommended scopes:

| Scope | Use when | Grouping target should usually include |
| --- | --- | --- |
| `host` | The risk applies to a host regardless of service. | IP or stable hostname. |
| `service` | The risk applies to one network service. | IP/host, port, protocol, and sometimes scheme. |
| `application` | The risk applies to one web app or virtual host. | Scheme, vhost/host, port, and app identity when known. |
| `endpoint` | The risk is tied to one URL/path or route. | Scheme, host, port, normalized path, and relevant parameters. |
| `cloud_resource` | The risk applies to one cloud object. | Provider, account/project, region, resource type, resource id/name. |

For CVE-oriented findings, the natural grouping is usually:

```text
finding_scope + normalized target at that scope + CVE/GHSA/vendor id
```

For findings without a CVE, use the finding class instead of the CVE:

```text
finding_scope + normalized target at that scope + finding class
```

### Multi-Page Same-CVE Example

Suppose a crawler observes the same CVE on several pages of one web server:

```text
https://example.test/
https://example.test/admin
https://example.test/login
```

If the vulnerability is really service-wide or application-wide, these should
be one report finding with multiple affected locations, not three unrelated
findings. The plugin should emit each observation with the same semantic
grouping key:

```json
{
  "finding_scope": "service",
  "group_key": "service|CVE-2026-1234|192.0.2.10|443|tcp",
  "identifiers": {"cve": ["CVE-2026-1234"]},
  "target": {
    "ip": "192.0.2.10",
    "port": "443",
    "protocol": "tcp",
    "scheme": "https",
    "host": "example.test"
  },
  "affected": [
    {"url": "https://example.test/admin"}
  ]
}
```

The report layer groups events with that `group_key` and can render one logical
finding. The `affected` entries remain as evidence or affected locations under
that group.

If the vulnerability is endpoint-specific, such as reflected XSS at a
particular route, use `finding_scope="endpoint"` and include the normalized path
in the grouping identity. In that case `/admin` and `/login` should usually be
separate findings.

## Promotion And Deduplication

Promotion answers: "does this fact deserve finding review?"

Deduplication answers: "have we already seen this finding?"

Both are needed. A promoter rule can emit a finding candidate from a raw fact.
`finding_dedupe` then correlates candidates and tool findings using stable
identifiers, target identity, and evidence fingerprints. Exact identifiers such
as CVE/CWE/GHSA/vendor IDs are preferred. Fuzzy text matching is limited to
low-confidence merge candidates.

The first implementation uses these normalized topics:

- `finding.candidate`
- `finding.new`
- `finding.duplicate`
- `finding.updated`
- `finding.merge_candidate`

Bundled commandlets may emit `finding.candidate` when a fact matches a small
review-worthy rule. For example, `portscanner` promotes exposed Telnet, and
`http_headers` promotes missing high-value HTTP security headers.
`git_expose_check` promotes exposed `.git/config` repository metadata. Future
work may add explicit `finding.confirmed` topics for stronger verification.

## Report Command

`report` is the operator inbox and scoped finding viewer.

```text
bywaf> report
bywaf> report new
bywaf> report pipeline=1
bywaf> report pipeline=1,2,3
bywaf> report job=7
bywaf> report run=12
```

Defaults are optimized for field use:

- `report` and `report new` show unreviewed findings from the latest pipeline
  that produced finding events.
- `report pipeline=...`, `report job=...`, and `report run=...` render scoped
  grouped findings without requiring manual event queries.
- `status=all` includes findings that have a `finding.reviewed` marker.

`finding_report` remains the table/export plugin for normalized finding streams
and file artifacts. `report` is the quick interactive view.

## Current Boundaries

The current report model is deliberately small. Durable report objects,
`report create/update/show/export`, acceptance/rejection triage, and resume
summaries for unreviewed completed work are planned follow-up pieces.

This avoids making reports duplicate finding payloads. Reports should remain
saved scopes, review state, and render/export instructions over canonical event
and artifact data.
