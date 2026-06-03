# Bundled Plugin Manual

This manual is the operator-facing guide to Bywaf's bundled plugins and
commandlets. It is organized by plugin family, then plugin, then commandlet.

Bywaf commandlet values use `name=value`. Bywaf-owned `--flags` are binary only.
For machine-readable contracts, inspect each plugin's `*.plugin.toml` manifest
or run `help <commandlet>` inside the Bywaf interpreter.

## Quick Reference

| Family | Plugin | Commandlets | Intended use | Example usage string | Detailed manual |
| --- | --- | --- | --- | --- | --- |
| OS | `os.ls` | `ls` | List local files. | `ls bywaf/plugins` | [os.ls](#osls) |
| OS | `os.cat` | `cat` | Print a local text file. | `cat README.md` | [os.cat](#oscat) |
| OS | `os.less` | `less` | Page through a local file. | `less README.md` | [os.less](#osless) |
| Discovery | `discovery.hostscanner` | `hostscanner` | Discover live hosts with nmap. | `hostscanner 192.0.2.0/24` | [discovery.hostscanner](#discoveryhostscanner) |
| Network | `network.portscanner` | `portscanner`, `ports` | Scan ports and inspect open-port results. | `portscanner port=22,80,443 host=192.0.2.10` | [network.portscanner](#networkportscanner) |
| Network | `network.service_probe` | `service_probe` | Classify services from passive facts. | `portscanner host=192.0.2.10 | service_probe` | [network.service_probe](#networkservice_probe) |
| Network | `network.tcp_banner` | `tcp_banner` | Capture TCP banners or HTTP HEAD responses. | `tcp_banner mode=http-head 192.0.2.10:8080` | [network.tcp_banner](#networktcp_banner) |
| Network | `network.management_exposure` | `management_exposure` | Promote exposed management surfaces. | `portscanner host=192.0.2.10 | service_probe | management_exposure` | [network.management_exposure](#networkmanagement_exposure) |
| Network | `network.ssh_probe` | `ssh_probe` | Probe SSH service/auth state. | `ssh_probe username=test password=test 192.0.2.10` | [network.ssh_probe](#networkssh_probe) |
| Network | `network.snmp_get` | `snmp_get` | Read one SNMP OID. | `snmp_get community=public oid=1.3.6.1.2.1.1.1.0 192.0.2.10` | [network.snmp_get](#networksnmp_get) |
| Network | `network.traceroute` | `traceroute` | Record route hops. | `traceroute 192.0.2.10` | [network.traceroute](#networktraceroute) |
| Recon | `recon.dns_lookup` | `dns_lookup` | Resolve DNS records. | `dns_lookup record-type=MX example.com` | [recon.dns_lookup](#recondns_lookup) |
| Recon | `recon.dns_enum` | `dns_enum` | Run starter DNS enumeration. | `dns_enum domain=example.com words=www,api` | [recon.dns_enum](#recondns_enum) |
| Recon | `recon.shodan_lookup` | `shodan_lookup` | Query Shodan by IP or search text. | `shodan_lookup mode=search apache country:US` | [recon.shodan_lookup](#reconshodan_lookup) |
| Identity | `identity.ldap_probe` | `ldap_probe` | Probe LDAP server metadata. | `ldap_probe username=user password=secret dc.example.test` | [identity.ldap_probe](#identityldap_probe) |
| Identity | `identity.smb_probe` | `smb_probe` | Probe SMB server metadata. | `smb_probe domain=EXAMPLE username=user password=secret dc.example.test` | [identity.smb_probe](#identitysmb_probe) |
| HTTP | `http.http_headers` | `http_headers` | Collect HTTP headers and header findings. | `http_headers ssl=true example.com` | [http.http_headers](#httphttp_headers) |
| HTTP | `http.http_probe` | `http_probe` | Publish reusable HTTP endpoint facts. | `http_probe https://example.com/` | [http.http_probe](#httphttp_probe) |
| HTTP | `http.http_paths` | `http_paths` | Check explicit or common web paths. | `http_paths paths=/.git/config,/.env https://example.com/` | [http.http_paths](#httphttp_paths) |
| HTTP | `http.repo_exposure` | `repo_exposure`, `git_expose_check` | Check for exposed repository metadata. | `http_probe https://example.com/ | repo_exposure` | [http.repo_exposure](#httprepo_exposure) |
| HTTP | `http.webfin` | `webfin` | Fingerprint web technologies. | `http_probe https://example.com/ | webfin` | [http.webfin](#httpwebfin) |
| HTTP | `http.tls_probe` | `tls_probe` | Collect TLS certificate and hygiene facts. | `tls_probe https://example.com/` | [http.tls_probe](#httptls_probe) |
| HTTP | `http.waf_detect` | `waf_detect` | Detect likely WAF/CDN signals. | `waf_detect https://example.com/` | [http.waf_detect](#httpwaf_detect) |
| HTTP | `http.nikto` | `nikto` | Wrap Nikto and normalize findings. | `http_probe https://example.com/ | nikto` | [http.nikto](#httpnikto) |
| HTTP | `http.eyewitness` | `eyewitness` | Capture web screenshots through EyeWitness. | `http_probe https://example.com/ | eyewitness` | [http.eyewitness](#httpeyewitness) |
| HTTP | `http.screenshotter` | `screenshotter` | Friendly EyeWitness-backed screenshot commandlet. | `http_probe https://example.com/ | screenshotter` | [http.screenshotter](#httpscreenshotter) |
| Wireless | `wireless.wifi_scan` | `wifi_scan` | Wrap Kismet-style wireless scans. | `wifi_scan interface=wlan0mon duration=60` | [wireless.wifi_scan](#wirelesswifi_scan) |
| Analysis | `analysis.finding_dedupe` | `finding_dedupe` | Normalize and deduplicate findings. | `nikto https://example.com/ | finding_dedupe` | [analysis.finding_dedupe](#analysisfinding_dedupe) |
| Analysis | `analysis.finding_report` | `finding_report` | Render finding tables and report artifacts. | `finding_report export=findings.md` | [analysis.finding_report](#analysisfinding_report) |
| Analysis | `analysis.report` | `report` | Review, accept, confirm, defer, or reject findings. | `report accept 1-3 pipeline=1` | [analysis.report](#analysisreport) |
| Analysis | `analysis.finding` | `finding` | Lower-level finding review actions. | `finding confirm 1-3 pipeline=1` | [analysis.finding](#analysisfinding) |
| Analysis | `analysis.yara_scan` | `yara_scan` | Scan files with YARA rules. | `yara_scan rule=webshells.yar shell.php` | [analysis.yara_scan](#analysisyara_scan) |
| Runtime | `runtime.artifact` | `artifact`, `search` | Manage evidence artifacts. | `artifact list step=12` | [runtime.artifact](#runtimeartifact) |
| Runtime | `runtime.bundle` | `bundle` | Build evidence/report bundles. | `bundle add name=client-a evidence commandlet=nikto,webfin` | [runtime.bundle](#runtimebundle) |
| Runtime | `runtime.audit` | `audit` | Inspect or export audit records. | `audit export file=audit.jsonl` | [runtime.audit](#runtimeaudit) |
| Runtime | `runtime.inventory` | `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`, `banners`, `paths`, `screenshots` | Inspect stored domain facts. | `web pipeline=1 --page` | [runtime.inventory](#runtimeinventory) |
| Runtime | `runtime.job` | `job` | Inspect and control background jobs. | `job --all` | [runtime.job](#runtimejob) |
| Runtime | `runtime.pipeline` | `pipeline` | Inspect and control pipelines. | `pipeline attach 1 portscanner step=1` | [runtime.pipeline](#runtimepipeline) |
| Runtime | `runtime.step` | `step` | Inspect pipeline steps. | `step --new` | [runtime.step](#runtimestep) |
| Runtime | `runtime.results` | `results`, `result` | Show what a scan found. | `results job=latest` | [runtime.results](#runtimeresults) |
| Runtime | `runtime.control` | `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop` | Control running or paused work. | `pause job=7` | [runtime.control](#runtimecontrol) |
| Runtime | `runtime.note` | `note` | Attach or show runtime notes. | `note add step=12 text=validated manually` | [runtime.note](#runtimenote) |
| Runtime | `runtime.name` | `name` | Attach human-friendly runtime names. | `name pipeline=1 client subnet scan` | [runtime.name](#runtimename) |
| Runtime | `runtime.key` | `key` | Manage signing keys. | `key generate name=firm-evidence` | [runtime.key](#runtimekey) |
| Runtime | `runtime.schemas` | `schemas` | Inspect active event schemas. | `schemas owner=plugin` | [runtime.schemas](#runtimeschemas) |
| Runtime | `runtime.watchdog` | `watchdog` | Monitor runtime health and stalled work. | `watchdog --session-service` | [runtime.watchdog](#runtimewatchdog) |
| Storage | `storage.db` | `db` | Manage the active event/artifact databases. | `db status` | [storage.db](#storagedb) |

## Plugin Families

### OS

#### `os.ls`

Lists local files from inside the Bywaf interpreter.

Commandlet: `ls`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<path>` | No | Local path to list. | `bywaf/plugins` |

- Visible output: prints a directory listing to the console.
- Emits: no event records; console output only.
- Intended use: quick filesystem inspection while staying in the same session.

#### `os.cat`

Prints a local text file.

Commandlet: `cat`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<path>` | Yes | Local text file path. | `README.md` |

- Visible output: prints the file contents to the console.
- Emits: no event records; console output only.
- Intended use: quick text inspection.

#### `os.less`

Opens the system pager for a local file when interactive.

Commandlet: `less`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<path>` | Yes | Local file path. | `USAGE.md` |

- Visible output: opens the file in the configured pager.
- Emits: framework file-page request.
- Intended use: longer text inspection without leaving Bywaf.

### Discovery

#### `discovery.hostscanner`

Discovers live hosts with nmap and publishes reusable host facts.

Commandlet: `hostscanner`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Host, range, or CIDR target. | `192.0.2.0/24` |
| `host=` | No | Single explicit host, name, range, or CIDR. | `192.0.2.10` |
| `arguments=` | No | nmap host discovery arguments. | `-sn` |
| `except=` | No | Hosts or ranges to exclude. | `192.0.2.5` |
| `limit=` | No | Maximum live hosts to emit. | `256` |
| `--silent` | No | Binary flag; suppress discovery alerts. | `--silent` |

- Visible output: prints discovery alerts for live hosts unless `--silent` is
  set.
- Emits: `host.found`, `name.resolved`.
- External dependency: `nmap`.
- Intended use: first step in network pipelines.

### Network

#### `network.portscanner`

Scans targets for open ports and renders stored open-port results.

Commandlet: `portscanner`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<host>` | No | Positional host, range, or CIDR target. | `192.0.2.10` |
| `host=` | No | Single explicit host to scan. | `192.0.2.10` |
| `port=` | No | Comma/range port list; omit for nmap defaults. | `22,80,443` |
| `ports=` | No | Compatibility alias for `port=`. | `1-1024` |
| `arguments=` | No | nmap port-scan arguments. | `-sT` |
| `except=` | No | Hosts to exclude from scans. | `192.0.2.5` |
| `--listen` | No | Binary flag; poll scoped upstream `host.found` events. | `--listen` |
| `listen-interval=` | No | Poll interval in seconds. | `1.0` |
| `listen-timeout=` | No | Seconds to listen; `0` means forever. | `30` |
| `--quiet` | No | Binary flag; suppress discovery alerts. | `--quiet` |
| `--silent` | No | Binary flag; suppress discovery alerts. | `--silent` |

- Consumes: `host.found`, `network.route.hop`.
- Visible output: prints open-port discovery alerts unless `--quiet` or
  `--silent` is set.
- Emits: `port.open`, selected `finding.candidate` events.
- External dependency: `nmap`.

Commandlet: `ports`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `job=` | No | Job selector. | `latest` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `step=` | No | Step selector. | `12` |
| `host=` | No | Host selector. | `192.0.2.10` |
| `port=` | No | Port selector. | `443` |
| `sort=` | No | Sort key. | `port` |
| `all=` | No | Include all rows. | `true` |
| `--last` | No | Binary flag; show latest relevant scope. | `--last` |
| `--new` | No | Binary flag; show newly observed rows. | `--new` |
| `--page` | No | Binary flag; page output. | `--page` |

- Consumes: `port.open`.
- Visible output: prints or pages a table of stored open ports.
- Emits: no event records; console or paged output only.

#### `network.service_probe`

Classifies services from existing open-port, banner, HTTP, or TLS facts.

Commandlet: `service_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress service alerts. | `--silent` |

- Consumes: `port.open`, `tcp.banner`, `http.endpoint`, `tls.certificate`.
- Visible output: prints detected-service alerts unless `--silent` is set.
- Emits: `service.detected`.

#### `network.tcp_banner`

Connects to TCP services and records short banners.

Commandlet: `tcp_banner`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit `host[:port]` target. | `192.0.2.10:8080` |
| `mode=` | No | Probe mode: `banner` or `http-head`. | `http-head` |
| `port=` | No | Explicit port for bare host arguments. | `8080` |
| `read-bytes=` | No | Maximum bytes to read. | `256` |
| `timeout=` | No | Connection and read timeout seconds. | `3` |
| `--silent` | No | Binary flag; suppress banner alerts. | `--silent` |

- Consumes: `port.open`.
- Visible output: prints captured-banner alerts unless `--silent` is set.
- Emits: `tcp.banner`.

#### `network.management_exposure`

Promotes existing port, service, banner, endpoint, and fingerprint facts into
finding candidates for exposed management surfaces.

Commandlet: `management_exposure`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress management exposure alerts. | `--silent` |

- Consumes: `port.open`, `service.detected`, `tcp.banner`, `http.endpoint`,
  `web.fingerprint`.
- Visible output: prints finding alerts for promoted management exposures unless
  `--silent` is set.
- Emits: `finding.candidate`.
- Safety boundary: passive only; no authentication, exploit, brute force, or
  added active probing.

#### `network.ssh_probe`

Probes SSH service metadata and optional credential behavior.

Commandlet: `ssh_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<host>` | No | SSH target host; upstream `port.open` may also supply targets. | `192.0.2.10` |
| `username=` | No | SSH username. | `test` |
| `password=` | No | SSH password; secret-capable. | `secret` |
| `port=` | No | SSH port. | `22` |
| `timeout=` | No | Connection timeout seconds. | `5` |

- Consumes: `port.open`.
- Visible output: usually quiet on success; failures surface as command errors
  or tool-error events.
- Emits: `ssh.service`, `tool.error`.
- Secret handling: `password=` is declared as a secret option.

#### `network.snmp_get`

Reads one SNMP OID from a target.

Commandlet: `snmp_get`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<host>` | Yes | SNMP target host. | `192.0.2.10` |
| `community=` | No | SNMP community string. | `public` |
| `oid=` | No | SNMP OID. | `1.3.6.1.2.1.1.1.0` |
| `port=` | No | SNMP UDP port. | `161` |
| `timeout=` | No | Timeout seconds. | `5` |

- Visible output: usually quiet on success; failures surface as command errors
  or tool-error events.
- Emits: `snmp.value`, `tool.error`.

#### `network.traceroute`

Records route hops to a target.

Commandlet: `traceroute`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Host or address to trace. | `192.0.2.10` |
| `binary=` | No | Traceroute executable. | `traceroute` |
| `maxhops=` | No | Maximum hops. | `30` |
| `timeout=` | No | Per-hop wait time in seconds. | `5` |
| `--silent` | No | Binary flag; suppress per-target alerts. | `--silent` |

- Consumes: `host.found`.
- Visible output: prints route-hop summary alerts unless `--silent` is set.
- Emits: `network.route.hop`, sometimes `host.found`, and `tool.error`.

### Recon

#### `recon.dns_lookup`

Resolves DNS records with dnspython.

Commandlet: `dns_lookup`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<name>` | Yes | DNS name to resolve. | `example.com` |
| `record-type=` | No | DNS record type. | `MX` |
| `resolver=` | No | Resolver IP address. | `1.1.1.1` |
| `timeout=` | No | DNS timeout seconds. | `5` |

- Visible output: usually quiet on success; DNS failures may appear as command
  errors or `dns.error` records.
- Emits: `dns.record`, `dns.error`, `tool.error`.

#### `recon.dns_enum`

Resolves explicit names or generated subdomains into host facts.

Commandlet: `dns_enum`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<name>` | No | DNS names to resolve. | `www.example.com` |
| `domain=` | No | Base domain for `words=`. | `example.com` |
| `words=` | No | Comma or whitespace separated subdomain words. | `www,api,mail` |
| `--silent` | No | Binary flag; suppress resolver alerts. | `--silent` |

- Visible output: prints resolver alerts unless `--silent` is set.
- Emits: `name.resolved`, `host.found`, `dns.error`.

#### `recon.shodan_lookup`

Queries Shodan by IP or search query.

Commandlet: `shodan_lookup`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<ip-or-query>` | Yes | IP address in host mode, or search terms in search mode. | `apache country:US` |
| `mode=` | No | Lookup mode: `host` or `search`. | `search` |
| `api-key=` | No | Shodan API key; secret-capable and defaults to `SHODAN_API_KEY`. | `shodan-api-key` |
| `limit=` | No | Maximum search results. | `10` |

- Visible output: usually quiet on success; lookup failures surface as command
  errors or tool-error events.
- Emits: `shodan.host`, `shodan.result`, `tool.error`.

### Identity

#### `identity.ldap_probe`

Probes LDAP server metadata.

Commandlet: `ldap_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<host>` | Yes | LDAP target host. | `dc.example.test` |
| `username=` | No | LDAP username. | `user` |
| `password=` | No | LDAP password; secret-capable. | `secret` |
| `base-dn=` | No | Optional LDAP search base. | `dc=example,dc=test` |
| `port=` | No | LDAP port. | `389` |
| `ssl=` | No | Use LDAPS: `true` or `false`. | `true` |
| `timeout=` | No | Connection timeout seconds. | `5` |

- Visible output: usually quiet on success; connection or bind problems surface
  as command errors or tool-error events.
- Emits: `ldap.server`, `tool.error`.

#### `identity.smb_probe`

Probes SMB server metadata.

Commandlet: `smb_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<host>` | Yes | SMB target host. | `dc.example.test` |
| `domain=` | No | SMB domain. | `EXAMPLE` |
| `username=` | No | SMB username. | `user` |
| `password=` | No | SMB password; secret-capable. | `secret` |
| `port=` | No | SMB port. | `445` |
| `timeout=` | No | Connection timeout seconds. | `5` |

- Visible output: usually quiet on success; connection or auth problems surface
  as command errors or tool-error events.
- Emits: `smb.server`, `tool.error`.

### HTTP

#### `http.http_headers`

Collects HTTP response headers and promotes missing high-value security headers.

Commandlet: `http_headers`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Target host; upstream `port.open` may also supply targets. | `example.com` |
| `port=` | No | Target port. | `443` |
| `ssl=` | No | Use HTTPS: `true` or `false`. | `true` |
| `timeout=` | No | Connection timeout seconds. | `5` |

- Consumes: `port.open`.
- Visible output: usually quiet on success; reportable missing-header issues are
  visible through `report` or `finding_report`.
- Emits: `http.headers`, `finding.candidate`.

#### `http.http_probe`

Probes HTTP endpoints and publishes reusable endpoint facts.

Commandlet: `http_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | URL, host, or upstream `port.open` target. | `https://example.com/` |
| `scheme=` | No | Scheme override: `auto`, `http`, or `https`. | `https` |
| `path=` | No | Request path. | `/login` |
| `method=` | No | HTTP method: `HEAD` or `GET`. | `GET` |
| `follow-redirects=` | No | Follow redirects: `true` or `false`. | `true` |
| `cookie-file=` | No | Netscape-format cookie file. | `cookies.txt` |
| `firefox-profile=` | No | Firefox profile directory or `cookies.sqlite`. | `~/.mozilla/firefox/profile` |
| `timeout=` | No | Request timeout seconds. | `5` |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` |
| `--silent` | No | Binary flag; suppress probe alerts. | `--silent` |

- Consumes: `port.open`.
- Visible output: prints probe alerts unless `--silent` is set.
- Emits: `http.endpoint`.

#### `http.http_paths`

Checks common or explicitly supplied HTTP paths.

Commandlet: `http_paths`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<url>` | No | Explicit base URL or host. | `https://example.com/` |
| `paths=` | No | Comma or whitespace separated paths. | `/.git/config,/.env` |
| `timeout=` | No | HTTP timeout seconds. | `5` |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` |
| `--silent` | No | Binary flag; suppress path alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints checked-path alerts unless `--silent` is set; promoted
  findings are visible through `report` or `finding_report`.
- Emits: `http.path`, `finding.candidate`.
- Findings: exposed `.git/config`, source maps, dependency metadata, cloud/app
  config files, sensitive config files, backup archives, database dumps, admin
  login surfaces, and selected environment endpoints.

#### `http.repo_exposure`

Checks HTTP endpoints for exposed repository metadata.

Commandlets: `repo_exposure`, `git_expose_check`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `target=` | No | Explicit URL or host selector. | `https://example.com/` |
| `timeout=` | No | Request timeout seconds. | `5` |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` |
| `--silent` | No | Binary flag; suppress exposure alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints exposed `.git/config` alerts unless `--silent` is set.
- Emits: `repo.git_config.checked`, `finding.candidate`.
- Findings: `web.exposure.git_config`.

#### `http.webfin`

Fingerprints web technologies from HTTP endpoints.

Commandlet: `webfin`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `timeout=` | No | Request timeout seconds. | `5` |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` |
| `--silent` | No | Binary flag; suppress fingerprint alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints fingerprint alerts unless `--silent` is set.
- Emits: `web.fingerprint`.

#### `http.tls_probe`

Collects TLS certificate and hygiene facts.

Commandlet: `tls_probe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit `host[:port]` or HTTPS URL target. | `example.com:443` |
| `port=` | No | Default TLS port for bare hosts. | `443` |
| `timeout=` | No | Connection timeout seconds. | `5` |
| `--silent` | No | Binary flag; suppress TLS alerts. | `--silent` |

- Consumes: `port.open`, `http.endpoint`.
- Visible output: prints TLS capture alerts unless `--silent` is set; promoted
  findings are visible through `report` or `finding_report`.
- Emits: `tls.certificate`, `tls.probe.error`, `finding.candidate`.
- Findings: expired certificates and hostname mismatches.

#### `http.waf_detect`

Detects likely web application firewall or CDN response signals.

Commandlet: `waf_detect`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `timeout=` | No | HTTP timeout seconds. | `5` |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` |
| `--silent` | No | Binary flag; suppress WAF alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints WAF detection alerts unless `--silent` is set.
- Emits: `web.waf.detected`.

#### `http.nikto`

Runs Nikto through the framework process API and normalizes selected output.

Commandlet: `nikto`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `binary=` | No | Nikto executable. | `nikto` |
| `plugins=` | No | Nikto plugin selector. | `@@DEFAULT` |
| `source=` | No | Endpoint source: `all`, `explicit`, or `webfin`. | `webfin` |
| `timeout=` | No | Seconds per target. | `300` |
| `tuning=` | No | Nikto tuning selector. | `x` |
| `--silent` | No | Binary flag; suppress finding alerts. | `--silent` |

- Consumes: `http.endpoint`, `web.fingerprint`.
- Visible output: prints finding alerts unless `--silent` is set and attaches
  raw Nikto output artifacts when available.
- Emits: `nikto.finding`, `vulnerability.found`,
  `vulnerability.potential`, artifacts for raw output.
- External dependency: `nikto`.

#### `http.eyewitness`

Wraps EyeWitness to capture web screenshots.

Commandlet: `eyewitness`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `binary=` | No | EyeWitness executable. | `eyewitness` |
| `output-dir=` | No | Directory for EyeWitness output. | `artifacts/eyewitness` |
| `source=` | No | Endpoint source: `all` or `explicit`. | `all` |
| `timeout=` | No | Seconds for the EyeWitness run. | `600` |
| `--silent` | No | Binary flag; suppress screenshot alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints screenshot alerts unless `--silent` is set and attaches
  screenshot artifacts when files are produced.
- Emits: `eyewitness.screenshot`, `web.screenshotted_host`, screenshot
  artifacts and raw tool output artifacts.
- External dependency: EyeWitness.

#### `http.screenshotter`

Friendly Bywaf commandlet name for the same EyeWitness screenshot workflow.

Commandlet: `screenshotter`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` |
| `binary=` | No | EyeWitness executable. | `eyewitness` |
| `output-dir=` | No | Directory for EyeWitness output. | `artifacts/screenshots` |
| `source=` | No | Endpoint source: `all` or `explicit`. | `all` |
| `timeout=` | No | Seconds for the EyeWitness run. | `600` |
| `--silent` | No | Binary flag; suppress screenshot alerts. | `--silent` |

- Consumes: `http.endpoint`.
- Visible output: prints screenshot alerts unless `--silent` is set and attaches
  screenshot artifacts when files are produced.
- Emits: `eyewitness.screenshot`, `web.screenshotted_host`, screenshot
  artifacts and raw tool output artifacts.
- External dependency: EyeWitness.

### Wireless

#### `wireless.wifi_scan`

Wraps Kismet-style wireless scanning and stores produced logs.

Commandlet: `wifi_scan`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `interface=` | Yes | Wireless capture interface. | `wlan0mon` |
| `binary=` | No | Kismet executable. | `kismet` |
| `duration=` | No | Scan duration seconds. | `60` |
| `log-types=` | No | Kismet log types. | `kismet,json` |
| `output-dir=` | No | Directory for Kismet output. | `artifacts/wifi` |
| `--silent` | No | Binary flag; suppress network alerts. | `--silent` |

- Visible output: prints wireless-network alerts unless `--silent` is set and
  attaches produced Kismet logs.
- Emits: `wifi.network`, `kismet.network`, artifacts for produced logs.
- External dependency: Kismet-compatible tooling.

### Analysis

#### `analysis.finding_dedupe`

Normalizes and deduplicates raw finding streams.

Commandlet: `finding_dedupe`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `file=` | No | Write and attach a JSON or Markdown dedupe summary. | `dedupe-summary.json` |
| `format=` | No | Summary format: `json` or `md`. | `md` |
| `limit=` | No | Maximum historical input events when no pipeline input exists. | `1000` |
| `threshold=` | No | Minimum fuzzy score for merge candidates. | `0.82` |
| `--silent` | No | Binary flag; suppress finding alerts. | `--silent` |

- Consumes: `finding.candidate`, `finding.confirmed`, Nikto and vulnerability
  topics.
- Visible output: prints a dedupe summary line and optional finding alerts
  unless `--silent` is set; attaches a summary artifact when `file=` is used.
- Emits: `finding.new`, `finding.duplicate`, `finding.updated`,
  `finding.merge_candidate`.

#### `analysis.finding_report`

Renders finding tables and exports report artifacts.

Commandlet: `finding_report`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `source=` | No | Finding source: `auto`, `dedupe`, `tools`, or `all`. | `dedupe` |
| `export=` | No | Write and attach a table file; format inferred from suffix. | `findings.md` |
| `file=` | No | Compatibility alias for `export=`. | `findings.xlsx` |
| `format=` | No | File format when suffix is ambiguous. | `md` |
| `limit=` | No | Maximum events to inspect when no pipeline input exists. | `1000` |
| `--candidates` | No | Binary flag; include merge candidates. | `--candidates` |

- Consumes: finding and vulnerability topics.
- Visible output: renders a findings table and writes/attaches an exported
  report artifact when `export=` or `file=` is used.
- Emits: table render requests and report artifacts when exported.

#### `analysis.report`

Operator finding inbox for reviewing and scoping report findings.

Commandlet: `report`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | No | `network`, `detail`, `accept`, `confirm`, `defer`, `reject`, `unconfirm`, `create`, `show`, or `update`. | `accept` |
| `<selection>` | No | Row index, range, or `all` for detail/review actions. | `1-3,7` |
| `pipeline=` | No | Pipeline id or comma-separated ids. | `1,2` |
| `job=` | No | Job id or comma-separated ids. | `7` |
| `step=` | No | Step id or comma-separated ids. | `12` |
| `name=` | No | Saved report scope name. | `quarterly` |
| `limit=` | No | Maximum events to inspect. | `1000` |
| `note=` | No | Operator review note; consumes the rest of the line. | `validated manually` |
| `page=` | No | Page rendered report output: `true` or `false`. | `false` |
| `sort=` | No | Group report rows by `finding` or `host`. | `host` |
| `status=` | No | Review status filter. | `open` |
| `--last` | No | Binary flag; show latest scan/reportable pipeline. | `--last` |
| `--new` | No | Binary flag; show newly introduced facts. | `--new` |
| `--accepted-first` | No | Binary flag; show accepted findings before other states. | `--accepted-first` |
| `--candidates-first` | No | Binary flag; show candidate or potential findings first. | `--candidates-first` |

- Consumes: finding lifecycle topics plus report context facts.
- Visible output: renders a compact finding inbox, detailed finding views, or
  network summary tables; review actions print action results/errors.
- Emits: `report.rendered`, `report.scope.saved`, `finding.reviewed`.

#### `analysis.finding`

Lower-level commandlet for confirming or unconfirming finding rows.

Commandlet: `finding`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | Finding action: `confirm` or `unconfirm`. | `confirm` |
| `<selection>` | Yes | Row index range or `all`. | `1-3` |
| `pipeline=` | No | Pipeline id or comma-separated ids. | `1` |
| `job=` | No | Job id or comma-separated ids. | `7` |
| `step=` | No | Step id or comma-separated ids. | `12` |
| `limit=` | No | Maximum events to inspect. | `1000` |
| `note=` | No | Operator review note. | `validated manually` |
| `sort=` | No | Report grouping used for row numbering. | `finding` |
| `status=` | No | Finding review status filter. | `open` |

- Consumes: finding lifecycle topics.
- Visible output: prints review action results or errors.
- Emits: `finding.reviewed`.

#### `analysis.yara_scan`

Scans files with YARA rules.

Commandlet: `yara_scan`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<file>` | Yes | File path to scan. | `shell.php` |
| `rule=` | Yes | YARA rule file. | `webshells.yar` |

- Visible output: usually quiet on success; matches are available through result
  views and failures surface as command errors or tool-error events.
- Emits: `yara.match`, `tool.error`.
- External dependency: `yara-python`.

### Runtime

#### `runtime.artifact`

Manages evidence artifacts in the paired artifact database.

Commandlet: `artifact`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | `import`, `attach`, `cat`, `show`, `list`, `export`, `replace`, `remove`, `search`, or `verify`. | `list` |
| `artifact=` | No | Artifact id selector. | `1` |
| `serial=` | No | Runtime serial selector. | `run-abc123` |
| `step=` | No | Step selector. | `12` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `job=` | No | Job selector. | `7` |
| `topic=` | No | Artifact topic selector. | `artifact.attached` |
| `file=` | No | File path for import, attach, replace, or export. | `snapshot.html` |
| `dir=` | No | Directory path for export. | `artifacts/` |
| `name=` | No | Human-friendly artifact name. | `Landing page` |
| `note=` | No | Artifact note. | `login screenshot` |
| `limit=` | No | Byte limit for `cat`. | `4096` |
| `encoding=` | No | Encoding for `cat`. | `utf-8` |
| `--page` | No | Binary flag; page list or cat output. | `--page` |

Commandlet: `search`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `name=` | No | Search artifact names. | `login` |
| `filename=` | No | Search artifact filenames. | `screenshot` |
| `note=` | No | Search artifact notes. | `cookie` |
| `content=` | No | Search artifact content. | `password` |
| `serial=` | No | Runtime serial selector. | `run-abc123` |
| `artifact=` | No | Artifact id selector. | `1` |
| `step=` | No | Step selector. | `12` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `job=` | No | Job selector. | `7` |
| `since=` | No | Start time or event selector. | `20260601` |
| `until=` | No | End time. | `20260603` |
| `--regexp` | No | Binary flag; treat search values as regular expressions. | `--regexp` |

- Visible output: `list`, `show`, `cat`, `search`, and `verify` print or page
  artifact details; write actions print action results.
- Emits: artifact lifecycle events.
- Intended use: retain and inspect evidence with provenance.

#### `runtime.bundle`

Builds evidence/report bundles for handoff.

Commandlet: `bundle`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | `create`, `add`, `list`, `show`, `seal`, `verify`, or `export`. | `add` |
| `name=` | Usually | Bundle name. | `client-a` |
| `<content-kind>` | For `add` | `audit`, `evidence`, or `reports`. | `evidence` |
| `topic=` | No | Topic selector for bundle content. | `finding.new` |
| `step=` | No | Step selector. | `12` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `job=` | No | Job selector. | `7` |
| `serial=` | No | Runtime serial selector. | `run-abc123` |
| `since=` | No | Start time or selector. | `20260601` |
| `until=` | No | End time or selector. | `20260603` |
| `commandlet=` | No | Commandlet selector. | `nikto,webfin` |
| `file=` | For `export` | Bundle export path. | `client-a.bundle.json` |
| `key=` | With `--sign` | Signing key name. | `firm-evidence` |
| `--sign` | No | Binary flag; sign a sealed bundle. | `--sign` |

- Visible output: prints bundle creation, add, seal, verify, show, list, and
  export summaries.
- Emits: `bundle.created`, `bundle.item.added`, `bundle.sealed`,
  `bundle.exported`.

#### `runtime.audit`

Inspects or exports audit records.

Commandlet: `audit`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | Audit action such as `show`, `list`, or `export`. | `export` |
| `file=` | For export | Export file path. | `audit.jsonl` |
| `topic=` | No | Topic selector. | `finding.new` |
| `step=` | No | Step selector. | `12` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `job=` | No | Job id or serial selector. | `7` |
| `serial=` | No | Runtime serial selector. | `run-abc123` |
| `format=` | No | Export format or `auto`. | `auto` |
| `limit=` | No | Maximum events to show or export. | `1000` |
| `--encrypt` | No | Binary flag; encrypt supported exports. | `--encrypt` |

- Visible output: prints selected audit records or export summaries; encrypted
  exports may prompt for a passphrase.
- Emits: export artifacts when applicable.

#### `runtime.inventory`

Provides compact domain-specific inventory views over stored facts.

Commandlets: `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`,
`banners`, `paths`, `screenshots`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `job=` | No | Job selector. | `7` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `step=` | No | Step selector. | `12` |
| `all=` | No | Include all rows. | `true` |
| `<selector>` | No | View-specific `key=value` selector. | `host=192.0.2.10` |
| `--last` | No | Binary flag; show latest relevant scope. | `--last` |
| `--new` | No | Binary flag; show newly observed rows. | `--new` |
| `--page` | No | Binary flag; page output. | `--page` |

- Consumes: domain-specific facts for each view.
- Visible output: prints or pages compact domain inventory tables.
- Emits: no event records; console or paged output only.

#### `runtime.job`

Inspects and controls background jobs.

Commandlet: `job`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<id>` | No | Job id or serial for show/control. | `7` |
| `<action>` | No | `cancel`, `end`, or `kill`. | `cancel` |
| `<selector>` | No | Runtime list selector. | `state=running` |
| `since=` | No | Event cursor or runtime selector. | `120` |
| `sort=` | No | Sort key. | `started` |
| `--all` | No | Binary flag; include inactive rows. | `--all` |
| `--new` | No | Binary flag; highlight new rows. | `--new` |
| `--page` | No | Binary flag; page output. | `--page` |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` |
| `--hard` | No | Binary flag; request hard control. | `--hard` |

- Visible output: prints or pages job lists/details and control-action results.
- Emits: console or paged output and framework control effects.

#### `runtime.pipeline`

Inspects and controls pipelines.

Commandlet: `pipeline`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<id>` | No | Pipeline id or serial for show/control. | `1` |
| `<action>` | No | `attach`, `cancel`, `end`, or `kill`. | `attach` |
| `<commandlet-tail>` | For `attach` | Commandlet and arguments to attach. | `portscanner step=1` |
| `<selector>` | No | Runtime list selector. | `state=running` |
| `since=` | No | Event cursor or runtime selector. | `30` |
| `sort=` | No | Sort key. | `started` |
| `--all` | No | Binary flag; include inactive rows. | `--all` |
| `--new` | No | Binary flag; highlight new rows. | `--new` |
| `--page` | No | Binary flag; page output. | `--page` |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` |
| `--hard` | No | Binary flag; request hard control. | `--hard` |

- Visible output: prints or pages pipeline lists/details and control-action
  results.
- Emits: console or paged output and framework control effects.

#### `runtime.step`

Inspects pipeline steps.

Commandlet: `step`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<id>` | No | Step id or serial for detail view. | `12` |
| `<selector>` | No | Runtime list selector. | `host=192.0.2.10` |
| `since=` | No | Event cursor or runtime selector. | `40` |
| `sort=` | No | Sort key. | `started` |
| `--all` | No | Binary flag; include inactive rows. | `--all` |
| `--new` | No | Binary flag; highlight new rows. | `--new` |

- Visible output: prints step lists or step detail output.
- Emits: no event records; console output only.

#### `runtime.results`

Shows what the latest or selected scan found.

Commandlets: `results`, `result`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `job=` | No | Job selector or `latest`. | `latest` |
| `pipeline=` | No | Pipeline selector. | `1` |
| `step=` | No | Step selector. | `12` |
| `all=` | No | Include all result topics. | `true` |
| `sort=` | No | Sort key for rendered results. | `port` |
| `interval=` | No | Follow polling interval seconds. | `1` |
| `once=` | No | Stop follow after one render. | `true` |
| `--follow` | No | Binary flag; follow result updates. | `--follow` |
| `--page` | No | Binary flag; page output. | `--page` |

- Visible output: prints or pages rendered scan result summaries.
- Emits: no event records; console or paged output only.

#### `runtime.control`

Requests or applies runtime control actions.

Commandlets: `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<target>` | Yes | `job=`, `pipeline=`, `step=`, or `serial=` selector. | `job=7` |
| `<action>` | For `signal` | Signal action. | `verbosity` |
| `<key=value>` | No | Optional signal payload. | `level=quiet` |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` |
| `--hard` | No | Binary flag; request hard control where supported. | `--hard` |
| `--listonly` | No | Binary flag; list resumable targets for `resume`. | `--listonly` |

- Visible output: prints control request/action results or errors.
- Emits: runtime control lifecycle events.

#### `runtime.note`

Shows or saves notes attached to jobs, pipelines, and pipeline steps.

Commandlet: `note`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `add` | No | Action token to create a note instead of showing notes. | `add` |
| `step=` | One target required | Step selector. | `12` |
| `pipeline=` | One target required | Pipeline selector. | `1` |
| `job=` | One target required | Job selector. | `7` |
| `text=` | For `note add` | Note text; consumes the rest of the line. | `validated manually` |
| `file=` | No | Input file for `add`, or output file when showing notes. | `notes.txt` |

- Visible output: shows selected notes, saves notes to a file, or prints add
  results.
- Emits: note lifecycle events.

#### `runtime.name`

Shows or assigns human-readable names to jobs, pipelines, and pipeline steps.

Commandlet: `name`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `step=` | One target required | Step selector. | `12` |
| `pipeline=` | One target required | Pipeline selector. | `1` |
| `job=` | One target required | Job selector. | `7` |
| `text=` | No | Explicit name text; consumes the rest of the line. | `client subnet scan` |
| `<name text>` | No | Natural trailing name text. | `client subnet scan` |

- Visible output: shows the current name or prints assignment results.
- Emits: `runtime.name.assigned`.

#### `runtime.key`

Manages signing keys for plugin and catalog trust workflows.

Commandlet: `key`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | `list`, `show`, `generate`, `import`, `export`, `remove`, or `test`. | `generate` |
| `<scope-token>` | For import/export | `public` or `private`. | `public` |
| `name=` | Usually | Key name. | `firm-evidence` |
| `file=` | For import/export | Key file path. | `firm-evidence.pub` |
| `scope=` | No | Key scope. | `user` |

- Visible output: prints key lists, key metadata, import/export/generation
  results, and test results; some actions prompt for passphrases.
- Emits: `key.generated`, `key.imported`, `key.removed`, `key.tested`.

#### `runtime.schemas`

Inspects the active event schema catalog.

Commandlet: `schemas`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `owner=` | No | `framework`, `plugin`, or `all`. | `plugin` |
| `topic=` | No | Topic prefix. | `web.` |
| `detail=` | No | Include field-level detail: `true` or `false`. | `true` |
| `sort=` | No | `topic`, `owner`, `used`, or prefixed with `-`. | `-used` |
| `--page` | No | Binary flag; page output. | `--page` |

- Visible output: prints or pages schema tables and optional field details.
- Emits: no event records; console or paged output only.

#### `runtime.watchdog`

Monitors runtime health, stalls, and error rates.

Commandlet: `watchdog`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `interval=` | No | Seconds between service checks. | `5` |
| `timeout=` | No | Seconds a job may run before warning. | `300` |
| `stall-threshold=` | No | Seconds without job events before warning. | `120` |
| `error-threshold=` | No | Number of error events before warning. | `10` |
| `--once` | No | Binary flag; run one check. | `--once` |
| `--session-service` | No | Binary flag; run as session service. | `--session-service` |
| `--silent` | No | Binary flag; suppress console alerts. | `--silent` |

- Visible output: prints watchdog alerts unless `--silent` is set; session
  service mode primarily reports through events/alerts.
- Emits: `watchdog.timeout`, `watchdog.stalled`, `watchdog.error_rate`.

### Storage

#### `storage.db`

Manages the active event database and paired artifact database.

Commandlet: `db`

| Option | Required? | Value | Sample value |
| --- | --- | --- | --- |
| `<action>` | Yes | `status`, `stats`, `path`, `checkpoint`, `vacuum`, `new`, `load`, `export`, `encrypt`, `decrypt`, or `rekey`. | `status` |
| `file=` | For `new`, `load`, `export` | Database path. | `client.sqlite3` |
| `--encrypt` | No | Binary flag; encrypt a new or exported database. | `--encrypt` |
| `--force` | No | Binary flag; bypass interactive confirmation where supported. | `--force` |

- Visible output: prints database status, stats, paths, maintenance summaries,
  load/export results, and passphrase prompts for encryption actions.
- Security note: SQLCipher encryption protects the main event DB and paired
  artifact DB at rest when enabled.
