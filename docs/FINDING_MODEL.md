# Finding And Report Model

## Document Index

- [Purpose](#purpose)
- [Facts, Candidates, And Findings](#facts-candidates-and-findings)
- [Finding Payload](#finding-payload)
- [Finding Classes](#finding-classes)
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
| Review state | `finding.reviewed` | Operator or framework review marker for a finding id | `report` and future triage flows |

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
| `class` | Bywaf finding class used for reporting and grouping, such as `web.header.missing_hsts`. |
| `title` | Operator-facing finding title. |
| `finding_scope` | Convenience scope name for deriving `target_scope`, such as `host`, `host_port`, `service`, `web_origin`, `web_app`, `web_route`, or `cloud_resource`. |
| `target_scope` | Preferred explicit grouping scope, such as `{"kind": "web_origin", "value": "https://example.test"}`. |
| `target` | Target identity, commonly host/port/path/scheme fields. |
| `identifiers` | CVE, CWE, GHSA, vendor IDs, or other stable identifiers. |
| `affected` | Specific affected locations or instances, such as URLs, paths, object names, or evidence references. |
| `group_key` | Optional plugin-provided grouping key when the plugin knows the semantic grouping better than the generic id hash. |
| `evidence` | Evidence snippets or references to artifact/event ids. |
| `sources` | Commandlets, tools, or topics that contributed evidence. |
| `subjects` | Optional map from payload paths to what each value describes, such as `target.host=host` or `evidence=explanation`. |

Commandlets may emit richer fact payloads. The normalized finding layer keeps a
stable subset so reporting does not depend on every tool's native schema.

Reports derive a broad operational severity class from `severity`; plugins do
not need to emit a separate field:

| Severity | Derived class | Meaning |
| --- | --- | --- |
| `info` | `informational` | Useful context, normally not triage-blocking. |
| `low` | `advisory` | Low-risk issue or hygiene concern. |
| `medium` | `review` | Needs operator review. |
| `high` | `urgent` | High-priority risk. |
| `critical` | `emergency` | Immediate attention. |

## Subjects

Subjects describe what an output value is about. They are not plugin roles,
access-control roles, Python types, or display colors. Plugins provide subjects
so report/render layers can decide how to label, group, or color values without
each plugin hard-coding terminal presentation.

`candidate_payload(...)` infers common subjects from canonical field names:

```json
{
  "target": {"host": "192.0.2.10", "port": 443},
  "subjects": {
    "title": "finding.title",
    "target.host": "host",
    "target.port": "port",
    "severity": "severity",
    "evidence": "evidence"
  }
}
```

Use `subject_value(...)` when the key alone is ambiguous:

```python
from bywaf.finding import candidate_payload, subject_value

payload = candidate_payload(
    title="Weak login wording",
    finding_class="web.auth.weak_login",
    target={"host": "example.test"},
    affected=[{"login": subject_value("username", "admin"), "path": "/admin"}],
    evidence=subject_value("explanation", "Nikto reported weak login wording."),
)
```

Starter subjects include `host`, `ip`, `port`, `protocol`, `url`, `path`,
`username`, `account`, `email`, `service`, `timestamp`, `comment`, `string`,
`cve`, `cwe`, `severity`, `finding.title`, `finding.class`, `finding.status`,
`evidence`, `explanation`, and `artifact`.

## Finding Classes

Bywaf uses a small dot-separated finding class taxonomy for report grouping,
triage, and developer familiarity. It is not a replacement for established
taxonomies. CVEs, GHSAs, CWEs, OWASP categories, CAPEC ids, and vendor advisory
ids belong in `identifiers`; `class` says what kind of thing Bywaf should group
and render.

Finding classes use lowercase dotted names:

```text
<domain>.<category>.<specific_issue>
```

Starter examples:

| Class | Typical external identifiers |
| --- | --- |
| `web.header.missing_hsts` | `CWE-319`, OWASP `A02:2021` |
| `web.header.missing_x_content_type_options` | `CWE-693`, OWASP `A05:2021` |
| `web.exposure.git_config` | `CWE-538`, OWASP `A05:2021` |
| `web.xss.reflected` | `CWE-79`, OWASP `A03:2021` |
| `service.telnet.exposed` | `CWE-319`, OWASP `A02:2021` |
| `service.tls.weak_protocol` | `CWE-327`, OWASP `A02:2021` |
| `cloud.aws.s3.public_bucket` | `CWE-284`, OWASP `A01:2021` |
| `repo.secret.api_key` | `CWE-798`, OWASP `A02:2021` |

Prefer an existing class when one fits. If not, add the narrowest dotted class
that describes the detector's behavior and put familiar external taxonomy ids
under `identifiers`.

## Finding Grouping

Grouping answers: "which finding events represent the same logical finding?"

The detector or plugin is responsible for deciding the finding's semantic
scope. The framework should not guess whether a CVE is host-wide, service-wide,
application-wide, endpoint-specific, or cloud-resource-specific from a URL
alone. The plugin should encode that decision in `target_scope`, or in
`finding_scope` plus `target` when the conventional derivation is enough.

Report grouping is intentionally mechanical:

1. Use `group_key` when present.
2. Otherwise derive a key from `class`, `target_scope`, and the highest-priority
   external identifier: `cve`, `ghsa`, `vendor`, `cwe`, `owasp`, then `capec`.
3. Otherwise derive a key from `class` and `target_scope`.
4. Otherwise use `finding_id`.
5. Otherwise fall back to the individual event id.

This keeps domain knowledge close to the detector while keeping the reporting
layer consistent.

Recommended scopes:

| Scope | Use when | Grouping target should usually include |
| --- | --- | --- |
| `host` | The risk applies to a host regardless of service. | IP or stable hostname. |
| `host_port` | The risk applies to a host/port pair without deeper service identity. | IP/host, port, and protocol. |
| `service` | The risk applies to one network service. | IP/host, port, protocol, and sometimes scheme. |
| `web_origin` | The risk applies to one web origin or virtual host. | Scheme, host, and non-default port. |
| `web_app` | The risk applies to one web app below an origin. | Scheme, host, non-default port, and app/base path. |
| `web_route` | The risk is tied to one URL/path or route. | Scheme, host, non-default port, normalized path, and relevant parameters. |
| `cloud_resource` | The risk applies to one cloud object. | Provider, account/project, region, resource type, resource id/name. |

For CVE-oriented findings, the natural grouping is usually:

```text
class + target_scope + CVE/GHSA/vendor id
```

For findings without a CVE, use the finding class instead of the CVE:

```text
class + target_scope
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
findings. The plugin should emit each observation with the same `target_scope`
and CVE:

```json
{
  "class": "web.xss.reflected",
  "target_scope": {"kind": "web_origin", "value": "https://example.test"},
  "identifiers": {"cve": ["CVE-2026-1234"]},
  "target": {
    "scheme": "https",
    "host": "example.test",
    "path": "/admin"
  },
  "affected": [
    {"url": "https://example.test/admin"}
  ]
}
```

The report layer derives this group key:

```text
web.xss.reflected|web_origin:https://example.test|cve:CVE-2026-1234
```

It can render one logical finding while preserving each `affected` entry as an
affected location or evidence item under that group. A plugin may still provide
an explicit `group_key` when its domain logic cannot be represented by the
standard class/scope/identifier model.

If the vulnerability is endpoint-specific, such as reflected XSS at a
particular route, use `target_scope.kind="web_route"` and include the normalized path
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

For the operator-facing command workflow, see [Reporting](REPORTING.md). This
model page documents the payload and grouping rules that make reporting work.

```text
bywaf> report
bywaf> report pipeline=1
bywaf> report pipeline=1,2,3
bywaf> report job=7
bywaf> report step=12
bywaf> report status=all
bywaf> report accept all pipeline=1
bywaf> report accept 1-3,7-9 pipeline=1
bywaf> report defer 4 pipeline=1 note=needs manual validation
bywaf> report reject 2 pipeline=1 note=false positive after retest
```

Defaults are optimized for field use:

- `report` shows unreviewed findings from the latest pipeline
  that produced finding events.
- `report pipeline=...`, `report job=...`, and `report step=...` render scoped
  grouped findings without requiring manual event queries.
- Every report view shows total, accepted, deferred, rejected, and unreviewed
  counts before rendering rows.
- The default status is `unreviewed`; use `status=all`, `status=accepted`,
  `status=deferred`, or `status=rejected` to inspect other review states.
- `report accept ...`, `report defer ...`, and `report reject ...` write
  `finding.reviewed` events. Selection values are row numbers from the current
  report view: `all`, `1`, `1-4`, or comma-separated mixes such as `1-3,7,9-11`.
- Use `note=` for operator context on a review decision. Put `note=` last when
  the note contains spaces.

`finding_report` remains the table/export plugin for normalized finding streams
and file artifacts. `report` is the quick interactive view.

## Current Boundaries

The current report model is deliberately small. Durable report objects,
`report create/update/show/export`, richer review workflows, and resume
summaries for unreviewed completed work are planned follow-up pieces.

This avoids making reports duplicate finding payloads. Reports should remain
saved scopes, review state, and render/export instructions over canonical event
and artifact data.
