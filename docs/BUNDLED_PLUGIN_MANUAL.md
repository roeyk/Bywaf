# Bundled Plugin Manual

This manual is the operator-facing guide to Bywaf's bundled plugin commandlets.
Use it to choose the right commandlet, see one working usage string, and jump to
the detailed notes for inputs, outputs, findings, and artifacts.

For machine-readable contracts, inspect each plugin's `*.plugin.toml` manifest
or run `help <commandlet>` inside the Bywaf interpreter.

## Quick Reference

| Plugin name | Intended use | Example usage string | Detailed manual |
| --- | --- | --- | --- |
| `ls` | List local files from inside Bywaf. | `ls bywaf/plugins` | [ls](#ls) |
| `cat` | Print a local text file. | `cat README.md` | [cat](#cat) |
| `less` | Page through a local file interactively. | `less README.md` | [less](#less) |
| `hostscanner` | Discover live hosts with nmap. | `hostscanner 192.0.2.0/24` | [hostscanner](#hostscanner) |
| `portscanner` / `ports` | Scan ports and inspect open-port results. | `portscanner port=22,80,443 host=192.0.2.10` | [portscanner and ports](#portscanner-and-ports) |
| `service_probe` | Classify services from open ports. | `portscanner host=192.0.2.10 | service_probe` | [service_probe](#service_probe) |
| `tcp_banner` | Capture TCP banners or HTTP HEAD responses. | `tcp_banner mode=http-head 192.0.2.10:8080` | [tcp_banner](#tcp_banner) |
| `management_exposure` | Promote exposed management surfaces from passive facts. | `portscanner host=192.0.2.10 | service_probe | management_exposure` | [management_exposure](#management_exposure) |
| `ssh_probe` | Probe SSH service/auth state. | `ssh_probe username=test password=test 192.0.2.10` | [ssh_probe](#ssh_probe) |
| `snmp_get` | Read one SNMP OID. | `snmp_get community=public oid=1.3.6.1.2.1.1.1.0 192.0.2.10` | [snmp_get](#snmp_get) |
| `traceroute` | Record route hops to a target. | `traceroute 192.0.2.10` | [traceroute](#traceroute) |
| `dns_lookup` | Resolve DNS records. | `dns_lookup record-type=MX example.com` | [dns_lookup](#dns_lookup) |
| `dns_enum` | Run starter DNS enumeration. | `dns_enum example.com` | [dns_enum](#dns_enum) |
| `shodan_lookup` | Query Shodan by IP or search text. | `shodan_lookup mode=search apache country:US` | [shodan_lookup](#shodan_lookup) |
| `ldap_probe` | Probe LDAP server metadata. | `ldap_probe dc.example.test` | [ldap_probe](#ldap_probe) |
| `smb_probe` | Probe SMB server metadata. | `smb_probe domain=EXAMPLE username=user password=secret dc.example.test` | [smb_probe](#smb_probe) |
| `http_headers` | Collect HTTP headers and missing-header findings. | `http_headers example.com` | [http_headers](#http_headers) |
| `http_probe` | Probe HTTP endpoints for reusable endpoint facts. | `http_probe https://example.com/` | [http_probe](#http_probe) |
| `http_paths` | Check explicit or common web paths. | `http_paths paths=/.git/config,/.env https://example.com/` | [http_paths](#http_paths) |
| `repo_exposure` / `git_expose_check` | Check HTTP endpoints for exposed repository metadata. | `http_probe https://example.com/ | repo_exposure` | [repo_exposure and git_expose_check](#repo_exposure-and-git_expose_check) |
| `webfin` | Fingerprint web technologies. | `http_probe https://example.com/ | webfin` | [webfin](#webfin) |
| `tls_probe` | Collect TLS certificate and hygiene facts. | `tls_probe https://example.com/` | [tls_probe](#tls_probe) |
| `waf_detect` | Detect likely web application firewall signals. | `waf_detect https://example.com/` | [waf_detect](#waf_detect) |
| `nikto` | Wrap Nikto and normalize web finding output. | `http_probe https://example.com/ | nikto` | [nikto](#nikto) |
| `eyewitness` / `screenshotter` | Capture web screenshots through EyeWitness. | `http_probe https://example.com/ | screenshotter` | [eyewitness and screenshotter](#eyewitness-and-screenshotter) |
| `wifi_scan` | Wrap Kismet-style wireless scans and attach logs. | `wifi_scan interface=wlan0mon duration=60` | [wifi_scan](#wifi_scan) |
| `finding_dedupe` | Normalize and deduplicate finding events. | `nikto https://example.com/ | finding_dedupe` | [finding_dedupe](#finding_dedupe) |
| `finding_report` | Render finding tables and export report artifacts. | `finding_report export=findings.md` | [finding_report](#finding_report) |
| `report` / `finding` | Review, accept, confirm, defer, or reject findings. | `report accept 1-3 pipeline=1` | [report and finding](#report-and-finding) |
| `yara_scan` | Scan files with YARA rules. | `yara_scan rule=webshells.yar shell.php` | [yara_scan](#yara_scan) |
| `artifact` / `search` | Import, attach, preview, verify, and export evidence artifacts. | `artifact list step=12` | [artifact and search](#artifact-and-search) |
| `bundle` | Build evidence/report bundles. | `bundle add name=client-a evidence commandlet=nikto,webfin` | [bundle](#bundle) |
| `audit` | Inspect or export audit records. | `audit list capabilities` | [audit](#audit) |
| `db` | Manage the active event and artifact databases. | `db status` | [db](#db) |
| `job` / `pipeline` / `step` / `results` | Inspect runtime work and outputs. | `results job=latest` | [runtime inspection](#runtime-inspection) |
| `cancel` / `pause` / `resume` / `stop` / `kill` / `signal` / `end` | Control running or paused jobs and pipelines. | `pause job=7` | [runtime control](#runtime-control) |
| `note` / `name` | Attach notes and human-friendly names. | `note step=12 note=validated manually` | [note and name](#note-and-name) |
| `key` | Generate, import, test, and remove signing keys. | `key generate` | [key](#key) |
| `schemas` | Inspect active event schemas. | `schemas owner=plugin` | [schemas](#schemas) |
| `watchdog` | Monitor runtime health and stalled work. | `watchdog --session-service` | [watchdog](#watchdog) |

## OS Helpers

### `ls`

Lists local files from inside the Bywaf interpreter.

- Main options/arguments: optional path.
- Emits: console output only.
- Intended use: quick filesystem inspection while staying in the same session.

### `cat`

Prints a local text file.

- Main options/arguments: file path.
- Emits: console output only.
- Intended use: quick text inspection.

### `less`

Opens the system pager for a local file when interactive.

- Main options/arguments: file path.
- Emits: framework file-page request.
- Intended use: longer text inspection without leaving Bywaf.

## Discovery

### `hostscanner`

Discovers live hosts with nmap and publishes reusable host facts.

- Main inputs: positional target or `host=`.
- Emits: `host.found`, `name.resolved`.
- External dependency: `nmap`.
- Intended use: first step in network pipelines.

## Network

### `portscanner` And `ports`

`portscanner` scans targets for open ports. `ports` renders stored `port.open`
events without running a new scan.

- Main inputs: `host=`, `port=`, optional `arguments=`, `--listen`,
  `--quiet` / `--silent`.
- Consumes: `host.found` when piped or listening.
- Emits: `port.open`, plus selected finding candidates for obvious exposed
  services.
- External dependency: `nmap`.
- Intended use: convert hosts into service targets.

### `service_probe`

Classifies services from existing open-port facts.

- Main inputs: `port.open` events or explicit host/port targets.
- Consumes: `port.open`.
- Emits: `service.detected`.
- Intended use: add service labels before downstream classification.

### `tcp_banner`

Connects to TCP services and records short banners.

- Main inputs: host:port targets or upstream `port.open` events.
- Main options: `mode=banner` or `mode=http-head`.
- Consumes: `port.open`.
- Emits: `tcp.banner`.
- Intended use: collect passive text evidence for service identification.

### `management_exposure`

Promotes existing port, service, banner, endpoint, and fingerprint facts into
finding candidates for exposed management surfaces.

- Consumes: `port.open`, `service.detected`, `tcp.banner`, `http.endpoint`,
  `web.fingerprint`.
- Emits: `finding.candidate`.
- Findings: Redis, Docker API, Kubernetes/kubelet, Memcached,
  Elasticsearch/OpenSearch, MongoDB, Grafana, Jenkins, Kibana, Prometheus, RDP,
  and WinRM management exposure classes.
- Intended use: turn already-collected passive facts into reportable findings.
- Safety boundary: does not authenticate, exploit, brute force, or add active
  probing.

### `ssh_probe`

Probes SSH service metadata and optional credential behavior.

- Main inputs: host targets or upstream `port.open` events.
- Main options: `username=`, `password=`.
- Emits: `ssh.service`.
- Secret handling: credential options are resolved through the framework secret
  path when configured as secret values.

### `snmp_get`

Reads one SNMP OID from a target.

- Main inputs: target host.
- Main options: `community=`, `oid=`.
- Emits: `snmp.value`.
- Intended use: safe, explicit SNMP checks.

### `traceroute`

Records route hops to a target.

- Main inputs: host target or upstream `host.found`.
- Consumes: `host.found`.
- Emits: `network.route.hop`, and sometimes `host.found` for discovered hops.
- External dependency: system traceroute tooling.

## Recon

### `dns_lookup`

Resolves DNS records.

- Main inputs: domain name.
- Main options: `record-type=`.
- Emits: `dns.record`, `dns.error`.

### `dns_enum`

Performs starter DNS enumeration.

- Main inputs: domain name.
- Emits: DNS-related result events.
- Intended use: collect common DNS names and records for follow-up.

### `shodan_lookup`

Queries Shodan by IP or search query.

- Main inputs: IP address or search query.
- Main options: `mode=host` / `mode=search`, `api-key=`.
- Emits: `shodan.host`, `shodan.result`.
- Secret handling: prefer `SHODAN_API_KEY` or a Bywaf secret variable for API
  keys.

## Identity

### `ldap_probe`

Probes LDAP server metadata.

- Main inputs: LDAP target.
- Main options: `username=`, `password=`.
- Emits: `ldap.server`.

### `smb_probe`

Probes SMB server metadata.

- Main inputs: SMB target.
- Main options: `domain=`, `username=`, `password=`.
- Emits: `smb.server`.

## HTTP

### `http_headers`

Collects HTTP response headers and promotes missing high-value security headers.

- Main inputs: target host or URL.
- Emits: `http.headers`, `finding.candidate`.
- Findings: missing HSTS and related header hygiene classes.

### `http_probe`

Probes HTTP endpoints and publishes reusable endpoint facts.

- Main inputs: URL or upstream `port.open`.
- Consumes: `port.open`.
- Emits: `http.endpoint`.
- Intended use: normalize reachable web endpoints for HTTP pipelines.

### `http_paths`

Checks common or explicitly supplied HTTP paths.

- Main inputs: base URL or upstream `http.endpoint`.
- Main options: `paths=`, `timeout=`, `user-agent=`, `--silent`.
- Consumes: `http.endpoint`.
- Emits: `http.path`, `finding.candidate`.
- Findings: exposed `.git/config`, source maps, dependency metadata, cloud/app
  config files, sensitive config files, backup archives, database dumps, admin
  login surfaces, and selected environment endpoints.
- Safety boundary: newer sensitive path families are explicit-path and
  marker-gated; findings keep metadata evidence and do not retain credential
  response bodies by default.

### `repo_exposure` And `git_expose_check`

Checks HTTP endpoints for exposed repository metadata.

- Main inputs: `target=` URL or upstream `http.endpoint`.
- Consumes: `http.endpoint`.
- Emits: `repo.git_config.checked`, `finding.candidate`.
- Findings: `web.exposure.git_config`.

### `webfin`

Fingerprints web technologies from HTTP endpoints.

- Main inputs: URL or upstream `http.endpoint`.
- Consumes: `http.endpoint`.
- Emits: `web.fingerprint`.
- Intended use: feed technology-aware follow-up checks.

### `tls_probe`

Collects TLS certificate and hygiene facts.

- Main inputs: URL, host:port, or upstream `http.endpoint` / `port.open`.
- Consumes: `http.endpoint`, `port.open`.
- Emits: `tls.certificate`, `tls.probe.error`, `finding.candidate`.
- Findings: expired certificates and hostname mismatches.

### `waf_detect`

Detects likely web application firewall signals.

- Main inputs: URL or upstream HTTP facts.
- Emits: WAF-related web facts.
- Intended use: annotate web targets before deeper testing.

### `nikto`

Runs Nikto through the framework process API and normalizes selected output.

- Main inputs: URL or upstream `http.endpoint` / `web.fingerprint`.
- Main options: `source=`.
- Consumes: `http.endpoint`, `web.fingerprint`.
- Emits: `nikto.finding`, `vulnerability.found`,
  `vulnerability.potential`, artifacts for raw output.
- External dependency: `nikto`.

### `eyewitness` And `screenshotter`

Wrap EyeWitness to capture web screenshots.

- Main inputs: URL or upstream `http.endpoint`.
- Main options: `output-dir=`, `source=`.
- Consumes: `http.endpoint`.
- Emits: `eyewitness.screenshot`, `web.screenshotted_host`, artifacts for
  screenshots and raw tool output.
- External dependency: EyeWitness.

## Wireless

### `wifi_scan`

Wraps Kismet-style wireless scanning and stores produced logs.

- Main inputs/options: `interface=`, `duration=`.
- Emits: `wifi.network`, `kismet.network`, artifacts for produced logs.
- External dependency: Kismet-compatible tooling.

## Analysis And Reporting

### `finding_dedupe`

Normalizes and deduplicates raw finding streams.

- Consumes: `finding.candidate`, `finding.confirmed`, Nikto and vulnerability
  topics.
- Emits: `finding.new`, `finding.duplicate`, `finding.updated`,
  `finding.merge_candidate`.
- Intended use: turn scanner output into grouped report findings.

### `finding_report`

Renders finding tables and exports report artifacts.

- Main options: `source=`, `export=`.
- Consumes: finding and vulnerability topics.
- Emits: table render requests and report artifacts when exported.

### `report` And `finding`

`report` is the operator finding inbox. `finding` provides lower-level finding
review actions.

- Main actions: view, detail, accept, confirm, defer, reject.
- Consumes: finding lifecycle topics.
- Emits: `finding.reviewed`, `report.rendered`.

### `yara_scan`

Scans files with YARA rules.

- Main inputs/options: target file path, `rule=`.
- Emits: `yara.match`.
- External dependency: `yara-python`.

## Runtime, Evidence, And Storage

### `artifact` And `search`

Manages evidence artifacts in the paired artifact database.

- Main actions: import, attach, list, show, cat, replace, remove, export,
  verify, search.
- Emits: artifact lifecycle events.
- Intended use: retain and inspect evidence with provenance.

### `bundle`

Builds evidence/report bundles for handoff.

- Main actions: create, add, seal, export.
- Consumes: report and artifact records.
- Emits: bundle lifecycle events.

### `audit`

Inspects or exports audit records.

- Main examples: `audit list capabilities`, `audit export file=audit.jsonl`.
- Emits: export artifacts when applicable.

### `db`

Manages the active event database and paired artifact database.

- Main actions: status, path, checkpoint, vacuum, new, load, export, encrypt,
  decrypt, rekey.
- Security note: SQLCipher encryption protects the main event DB and paired
  artifact DB at rest when enabled.

### Runtime Inspection

`job`, `pipeline`, `step`, and `results` inspect runtime work and outputs.

- Intended use: find latest jobs, inspect steps, and render compact result
  summaries without rereading raw events.

### Runtime Control

`cancel`, `pause`, `resume`, `stop`, `kill`, `signal`, and `end` request or
apply runtime control actions.

- Intended use: manage long-running jobs and pipelines.
- Emits: runtime control lifecycle events.

### `note` And `name`

Attach human notes and stable friendly names to runtime objects.

- Main options: `job=`, `pipeline=`, `step=`, `note=`.
- Emits: note/name lifecycle events.

### `key`

Manages signing keys for plugin and catalog trust workflows.

- Main actions: generate, import, test, remove.
- Intended use: maintainer and reviewed plugin distribution workflows.

### `schemas`

Inspects the active event schema catalog.

- Main options: `owner=`.
- Intended use: see what event topics and fields commandlets produce/consume.

### `watchdog`

Monitors runtime health, stalls, and error rates.

- Main use: session service started by trigger rules after network activity, or
  explicit `watchdog --session-service`.
- Emits: `watchdog.timeout`, `watchdog.stalled`, `watchdog.error_rate`.
