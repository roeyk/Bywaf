# Framework Surface

This document enumerates the named resources exposed by the base Bywaf
installation: capabilities, trigger rules, plugin data topics, and
framework-owned event/audit topics. It is intended as an operator and
plugin-author reference for names that appear in manifests, audit output,
trigger predicates, and commandlet code.

Read each table as a resource map: the stable dotted name is the identifier,
the associated provider or commandlet shows ownership, and the purpose or
consumer columns describe why the name exists and what code normally uses it.

## Document Index

- [Capabilities](#capabilities)
- [Trigger Rules](#trigger-rules)
- [Plugin Data Topics](#plugin-data-topics)
- [Framework Audit And Control Topics](#framework-audit-and-control-topics)
- [Notes](#notes)

## Capabilities

Capabilities are declared by commandlets and audited with
`plugin.capability.used` or `plugin.capability.missing` when code asks the
framework to perform privileged actions. The associated commandlets are the
base installation commandlets that declare or use each capability.

| Capability | Base commandlets |
| --- | --- |
| `artifact.read` | `artifact`, `bundle`, `search` |
| `artifact.write` | `artifact`, `eyewitness`, `finding_dedupe`, `finding_report`, `nikto`, `wifi_scan` |
| `db.manage` | `db` |
| `db.raw` | `audit`, `db` |
| `db.read:*` | `watchdog` |
| `db.read:artifact.attached` | `artifact` |
| `db.read:bundle.created` | `bundle` |
| `db.read:bundle.item.added` | `bundle` |
| `db.read:bundle.sealed` | `bundle` |
| `db.read:finding.candidate` | `finding_dedupe`, `finding_report`, `report` |
| `db.read:finding.merge_candidate` | `finding_report`, `report` |
| `db.read:finding.new` | `finding_report`, `report` |
| `db.read:finding.reviewed` | `report` |
| `db.read:nikto.finding` | `finding_dedupe`, `finding_report` |
| `db.read:vulnerability.confirmed` | `finding_dedupe`, `finding_report` |
| `db.read:vulnerability.false_positive` | `finding_dedupe`, `finding_report` |
| `db.read:vulnerability.found` | `finding_dedupe`, `finding_report` |
| `db.read:vulnerability.potential` | `finding_dedupe`, `finding_report` |
| `db.read:vulnerability.speculative` | `finding_dedupe`, `finding_report` |
| `db.write:bundle.created` | `bundle` |
| `db.write:bundle.exported` | `bundle` |
| `db.write:bundle.item.added` | `bundle` |
| `db.write:bundle.sealed` | `bundle` |
| `db.write:dns.error` | `dns_lookup` |
| `db.write:dns.record` | `dns_lookup` |
| `db.write:eyewitness.screenshot` | `eyewitness` |
| `db.write:finding.candidate` | `http_headers`, `portscanner` |
| `db.write:finding.duplicate` | `finding_dedupe` |
| `db.write:finding.merge_candidate` | `finding_dedupe` |
| `db.write:finding.new` | `finding_dedupe` |
| `db.write:finding.updated` | `finding_dedupe` |
| `db.write:key.generated` | `key` |
| `db.write:key.imported` | `key` |
| `db.write:key.removed` | `key` |
| `db.write:key.tested` | `key` |
| `db.write:kismet.network` | `wifi_scan` |
| `db.write:ldap.server` | `ldap_probe` |
| `db.write:network.error` | `nikto` |
| `db.write:nikto.finding` | `nikto` |
| `db.write:report.rendered` | `report` |
| `db.write:name.resolved` | `hostscanner` |
| `db.write:shodan.host` | `shodan_lookup` |
| `db.write:shodan.result` | `shodan_lookup` |
| `db.write:smb.server` | `smb_probe` |
| `db.write:snmp.value` | `snmp_get` |
| `db.write:ssh.service` | `ssh_probe` |
| `db.write:system.error` | `eyewitness`, `nikto`, `wifi_scan` |
| `db.write:tool.error` | `eyewitness`, `ldap_probe`, `nikto`, `shodan_lookup`, `smb_probe`, `snmp_get`, `ssh_probe`, `wifi_scan`, `yara_scan` |
| `db.write:tool.exception` | `nikto` |
| `db.write:vulnerability.found` | `nikto` |
| `db.write:vulnerability.potential` | `nikto` |
| `db.write:watchdog.error_rate` | `watchdog` |
| `db.write:watchdog.stalled` | `watchdog` |
| `db.write:watchdog.timeout` | `watchdog` |
| `db.write:web.error` | `nikto` |
| `db.write:web.screenshot` | `eyewitness` |
| `db.write:wifi.network` | `wifi_scan` |
| `db.write:yara.match` | `yara_scan` |
| `filesystem.read` | `artifact`, `cat`, `db`, `eyewitness`, `finding_dedupe`, `finding_report`, `http_probe`, `key`, `less`, `ls`, `nikto`, `note`, `wifi_scan`, `yara_scan` |
| `filesystem.write` | `artifact`, `audit`, `bundle`, `db`, `eyewitness`, `finding_dedupe`, `finding_report`, `key`, `nikto`, `note`, `wifi_scan` |
| `framework.console.alert` | `eyewitness`, `hostscanner`, `http_probe`, `nikto`, `portscanner`, `watchdog`, `webfin`, `wifi_scan` |
| `framework.console.output` | `artifact`, `audit`, `bundle`, `cancel`, `cat`, `db`, `end`, `finding_dedupe`, `job`, `key`, `kill`, `ls`, `name`, `note`, `pause`, `pipeline`, `report`, `resume`, `search`, `signal`, `stop` |
| `framework.file.page` | `less` |
| `framework.job.control` | `cancel`, `end`, `job`, `kill`, `pause`, `pipeline`, `resume`, `signal`, `stop` |
| `framework.pipeline.control` | `cancel`, `end`, `kill`, `pause`, `pipeline`, `resume`, `signal`, `stop` |
| `framework.process.run` | `eyewitness`, `nikto`, `wifi_scan` |
| `framework.render.table` | `finding_report` |
| `framework.secret.resolve` | `ldap_probe`, `shodan_lookup`, `smb_probe`, `ssh_probe` |
| `network.connect` | `dns_lookup`, `eyewitness`, `hostscanner`, `http_headers`, `http_probe`, `ldap_probe`, `nikto`, `portscanner`, `shodan_lookup`, `smb_probe`, `snmp_get`, `ssh_probe`, `webfin` |
| `network.listen` | `wifi_scan` |
| `process.run` | `eyewitness`, `nikto`, `wifi_scan` |

## Trigger Rules

Trigger ids are provider-scoped. The local trigger name only needs to be unique
inside the provider that defines it. A fully qualified trigger id uses
`<provider>.<local-trigger-name>` so plugin authors can keep local names concise
without colliding with other providers.

| Trigger id | Trigger for | Provider | Source topic | Predicate | Used by / effect |
| --- | --- | --- | --- | --- | --- |
| `runtime.watchdog.network-access-starts-watchdog` | Starting the session watchdog only after network activity is observed | `runtime.watchdog` | `plugin.capability.used` | `capability == "network.connect"` and the event belongs to an active job; excludes `watchdog`; suppresses self-triggering | Runs `watchdog --session-service` as a `service` action; operators inspect it with `triggers`; lifecycle is audited with `framework.trigger.*` topics |

## Plugin Data Topics

These topics are declared by bundled commandlets through their `CommandSpec`
`consumes` and `emits` fields. In this table, `Emits` is the producer side of
the association and `Consumes` is the normal consumer side.

| Commandlet | Consumes | Emits |
| --- | --- | --- |
| `bundle` | none | `bundle.created`, `bundle.item.added`, `bundle.sealed`, `bundle.exported` |
| `dns_lookup` | none | `dns.record`, `dns.error` |
| `eyewitness` | `http.endpoint` | `eyewitness.screenshot`, `web.screenshot` |
| `finding_dedupe` | `finding.candidate`, `nikto.finding`, `vulnerability.found`, `vulnerability.potential`, `vulnerability.confirmed`, `vulnerability.speculative`, `vulnerability.false_positive` | `finding.new`, `finding.duplicate`, `finding.updated`, `finding.merge_candidate` |
| `finding_report` | `finding.candidate`, `finding.new`, `finding.merge_candidate`, `nikto.finding`, `vulnerability.found`, `vulnerability.potential`, `vulnerability.confirmed`, `vulnerability.speculative`, `vulnerability.false_positive` | `framework.render.table.requested`, `artifact.attached` |
| `hostscanner` | none | `name.resolved`, `host.found` |
| `http_headers` | `port.open` | `http.headers`, `finding.candidate` |
| `http_probe` | `port.open` | `http.endpoint` |
| `key` | none | `key.generated`, `key.imported`, `key.removed`, `key.tested` |
| `ldap_probe` | none | `ldap.server` |
| `nikto` | `http.endpoint`, `web.fingerprint` | `nikto.finding`, `vulnerability.found`, `vulnerability.potential` |
| `portscanner` | `host.found` | `port.open`, `finding.candidate` |
| `report` | `finding.candidate`, `finding.new`, `finding.merge_candidate` | `report.rendered` |
| `shodan_lookup` | none | `shodan.host`, `shodan.result` |
| `smb_probe` | none | `smb.server` |
| `snmp_get` | none | `snmp.value` |
| `ssh_probe` | `port.open` | `ssh.service` |
| `watchdog` | none | `watchdog.timeout`, `watchdog.stalled`, `watchdog.error_rate` |
| `webfin` | `http.endpoint` | `web.fingerprint` |
| `wifi_scan` | none | `wifi.network`, `kismet.network` |
| `yara_scan` | none | `yara.match` |

## Framework Audit And Control Topics

Framework topics are emitted by the runtime, plugin context helpers, trust
checks, resource commands, and runtime-control commandlets.

| Topic group | Topics | Associated with | Used by / purpose |
| --- | --- | --- | --- |
| Artifact lifecycle | `artifact.imported`, `artifact.attached`, `artifact.exported`, `artifact.removed`, `artifact.replaced` | Artifact commandlets and artifact-backed plugin output | Tracks evidence files, provenance attachment, exported artifacts, replacement, and removal for audit and bundle/report consumers |
| Bundle lifecycle | `bundle.created`, `bundle.exported`, `bundle.item.added`, `bundle.sealed` | `bundle` commandlet | Records client deliverable composition, sealing, and export activity |
| Capability audit | `plugin.capability.used`, `plugin.capability.missing` | Plugin context helpers and capability enforcement | Shows observed privileged behavior; triggers can watch these topics, for example network access starting the watchdog |
| Command run lifecycle | `command.run.arguments`, `command.run.completed`, `command.run.failed` | Runner and runtime store | Reconstructs command execution, captured arguments, and terminal run status |
| Framework requests | `framework.console.alert.requested`, `framework.console.output.requested`, `framework.file.page.requested`, `framework.process.run.requested`, `framework.process.stream.requested`, `framework.render.table.requested`, `framework.request.denied` | Plugin context request helpers | Lets plugins ask the interpreter/frontend for privileged actions without directly owning terminal, process, paging, or rendering behavior |
| Framework expansion/audit | `framework.argument.expanded`, `framework.secret.argv`, `framework.variable.expanded` | Shell parser, secret resolver, variable expansion | Explains how command input changed before a commandlet received it, with secret-safe audit metadata |
| Job lifecycle | `job.requested`, `job.claimed`, `job.claim.denied`, `job.started`, `job.finished`, `job.failed`, `job.pause.requested`, `job.resume.requested`, `job.stop.requested` | Shell, runner, job-control commandlets | Records scheduling, ownership, execution status, and operator control requests |
| Plugin catalog trust | `plugin.catalog.verified`, `plugin.catalog.rejected`, `plugin.catalog.entry.verified`, `plugin.catalog.entry.rejected` | Plugin catalog verifier | Audits catalog and per-entry trust decisions before plugin loading |
| Plugin manifest trust | `plugin.manifest.verified`, `plugin.manifest.rejected` | Plugin manifest verifier | Audits signed manifest decisions before plugin import |
| Plugin progress | `plugin.progress` | Long-running commandlets | Provides structured progress updates for the shell, logs, and future frontends |
| Policy | `policy.evaluated` | Policy and plan approval flow | Records whether a requested action was allowed, denied, or required approval |
| Process audit | `process.started`, `process.exited`, `process.secret.argv` | Framework-mediated process execution | Tracks external tools, exit status, and secret-safe argument handling |
| Report lifecycle | `report.rendered` | `report` commandlet | Records which finding events were rendered for an operator-facing report view |
| Resource commands | `resource.plugin.loaded`, `resource.script.command` | `load` and script execution | Records plugin loads and script commands executed through the shell |
| Runtime naming | `runtime.name.assigned` | `name` commandlet and runtime metadata | Associates human-friendly names with runtime objects |
| Runtime signals | `runtime.signal.requested`, `runtime.signal.applied`, `runtime.signal.ignored` | `signal`, `pause`, `resume`, `cancel`, `kill`, `stop`, and cooperative commandlets | Traces requested runtime controls and whether target jobs/runs applied or ignored them |
| Shell execution | `shell.exec.started`, `shell.exec.completed`, `shell.exec.failed` | `exec` command | Records operator-requested OS shell commands separately from Bywaf commandlet runs |
| Trigger lifecycle | `framework.trigger.enabled`, `framework.trigger.fired`, `framework.trigger.disabled` | Trigger registry and provider-owned trigger rules | Shows which trigger rule became active, which source event fired it, and when it was disabled |

## Notes

- `db.read:<topic>` and `db.write:<topic>` capabilities are topic-scoped
  database permissions.
- `db.read:*` is a wildcard read capability and should be reserved for
  framework services that need broad event visibility.
- Request topics ending in `.requested` are framework-mediated actions. A
  commandlet publishes the request; the shell/runtime handles it only when the
  commandlet declared the matching framework capability.
