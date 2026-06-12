# Bundled Plugin Manual

This manual is the operator-facing guide to Bywaf's bundled plugins and
commandlets. It is organized by plugin family, then plugin, then commandlet.

Bywaf commandlet values use `name=value`. Bywaf-owned `--flags` are binary only.
For machine-readable contracts, inspect each plugin's `*.plugin.toml` manifest
or run `help <commandlet>` inside the Bywaf interpreter.

## Terminology

A **plugin** is the packaged Bywaf feature unit. It owns metadata, capability declarations, event contracts, dependencies, and one or more commandlets. Example: `network.portscanner`.

A **commandlet** is an operator-facing command exposed by a plugin. Example: `portscanner` and `ports` are commandlets provided by the `network.portscanner` plugin.

A **provider** is the Python implementation object or module that registers or returns commandlets to the framework. It is mostly an implementation detail for plugin authors and maintainers. Operators usually care about plugins and commandlets, not providers.

## Table Of Contents

<div class="plugin-toc">
<div class="toc-header"><span class="toc-count">Plugins (Commandlets)</span><span class="toc-name">Name</span></div>
<details class="plugin-toc-family">
<summary id="toc-analysis"><span class="toc-count">6</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Analysis</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfinding">analysis.finding</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfindingdedupe">analysis.finding.dedupe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfindingreport">analysis.finding.report</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisreport">analysis.report</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#analysistechnology_indicators">analysis.technology_indicators</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisyara_scan">analysis.yara_scan</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-discovery"><span class="toc-count">1</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Discovery</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#discoveryhostscanner">discovery.hostscanner</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-http"><span class="toc-count">14</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">HTTP</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpeyewitness">http.eyewitness</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpauth">http.auth</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpcors">http.cors</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpheaders">http.headers</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpmethods">http.methods</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httppaths">http.paths</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpprobe">http.probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpnikto">http.nikto</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#httprepo_exposure">http.repo_exposure</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpscreenshotter">http.screenshotter</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httptls_probe">http.tls_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpwaf_detect">http.waf_detect</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpwafw00f">http.wafw00f</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpwebfin">http.webfin</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-identity"><span class="toc-count">2</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Identity</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#identityldap_probe">identity.ldap_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#identitysmb_probe">identity.smb_probe</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-network"><span class="toc-count">7</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Network</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networkmanagement_exposure">network.management_exposure</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#networkportscanner">network.portscanner</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networkservice_probe">network.service_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networksnmp_get">network.snmp_get</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networkssh_probe">network.ssh_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networktcp_banner">network.tcp_banner</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#networktraceroute">network.traceroute</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-os"><span class="toc-count">3</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">OS</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#oscat">os.cat</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#osless">os.less</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#osls">os.ls</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-recon"><span class="toc-count">3</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Recon</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#recondns_enum">recon.dns_enum</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#recondns_lookup">recon.dns_lookup</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#reconshodan_lookup">recon.shodan_lookup</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-runtime"><span class="toc-count">14</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Runtime</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#runtimeartifact">runtime.artifact</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimeaudit">runtime.audit</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimebundle">runtime.bundle</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">7</span><span class="toc-name"><a href="#runtimecontrol">runtime.control</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">10</span><span class="toc-name"><a href="#runtimeinventory">runtime.inventory</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimejob">runtime.job</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimekey">runtime.key</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimename">runtime.name</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimenote">runtime.note</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimepipeline">runtime.pipeline</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#runtimeresults">runtime.results</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimeschemas">runtime.schemas</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimestep">runtime.step</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#runtimewatchdog">runtime.watchdog</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-storage"><span class="toc-count">1</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Storage</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#storagedb">storage.db</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-wireless"><span class="toc-count">1</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Wireless</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#wirelesswifi_scan">wireless.wifi_scan</a></span></div>
</details>
</div>

## Quick Reference

| Family | Plugin | Commandlets | Intended use | Example usage string | Detailed manual |
| --- | --- | --- | --- | --- | --- |
| OS | `os.ls` | `ls` | List local files. | `ls bywaf/plugins` | [os.ls](#osls) |
| OS | `os.cat` | `cat` | Print a local text file. | `cat README.md` | [os.cat](#oscat) |
| OS | `os.less` | `less` | Page through a local file. | `less README.md` | [os.less](#osless) |
| Discovery | `discovery.hostscanner` | `hostscanner` | Discover live hosts with nmap. | `hostscanner 192.0.2.0/24` | [discovery.hostscanner](#discoveryhostscanner) |
| Network | `network.portscanner` | `portscanner`, `ports` | Scan ports and inspect open-port results. | `portscanner port=22,80,443 host=192.0.2.10` | [network.portscanner](#networkportscanner) |
| Network | `network.service_probe` | `service_probe` | Classify services from passive facts. | `portscanner host=192.0.2.10 \| service_probe` | [network.service_probe](#networkservice_probe) |
| Network | `network.tcp_banner` | `tcp_banner` | Capture TCP banners or HTTP HEAD responses. | `tcp_banner mode=http-head 192.0.2.10:8080` | [network.tcp_banner](#networktcp_banner) |
| Network | `network.management_exposure` | `management_exposure` | Promote exposed management surfaces. | `portscanner host=192.0.2.10 \| service_probe \| management_exposure` | [network.management_exposure](#networkmanagement_exposure) |
| Network | `network.ssh_probe` | `ssh_probe` | Probe SSH service/auth state. | `ssh_probe username=test password=test 192.0.2.10` | [network.ssh_probe](#networkssh_probe) |
| Network | `network.snmp_get` | `snmp_get` | Read one SNMP OID. | `snmp_get community=public oid=1.3.6.1.2.1.1.1.0 192.0.2.10` | [network.snmp_get](#networksnmp_get) |
| Network | `network.traceroute` | `traceroute` | Record route hops. | `traceroute 192.0.2.10` | [network.traceroute](#networktraceroute) |
| Recon | `recon.dns_lookup` | `dns_lookup` | Resolve DNS records. | `dns_lookup record-type=MX example.com` | [recon.dns_lookup](#recondns_lookup) |
| Recon | `recon.dns_enum` | `dns_enum` | Run starter DNS enumeration. | `dns_enum domain=example.com words=www,api` | [recon.dns_enum](#recondns_enum) |
| Recon | `recon.shodan_lookup` | `shodan_lookup` | Query Shodan by IP or search text. | `shodan_lookup mode=search apache country:US` | [recon.shodan_lookup](#reconshodan_lookup) |
| Identity | `identity.ldap_probe` | `ldap_probe` | Probe LDAP server metadata. | `ldap_probe username=user password=secret dc.example.test` | [identity.ldap_probe](#identityldap_probe) |
| Identity | `identity.smb_probe` | `smb_probe` | Probe SMB server metadata. | `smb_probe domain=EXAMPLE username=user password=secret dc.example.test` | [identity.smb_probe](#identitysmb_probe) |
| HTTP | `http.auth` | `http_auth` | Probe HTTP auth challenges and passive auth posture findings. | `http_auth https://example.com/admin` | [http.auth](#httpauth) |
| HTTP | `http.headers` | `http_headers` | Collect HTTP headers and header findings. | `http_headers ssl=true example.com` | [http.headers](#httpheaders) |
| HTTP | `http.methods` | `http_methods` | Probe allowed HTTP methods and risky method findings. | `http_methods https://example.com/` | [http.methods](#httpmethods) |
| HTTP | `http.probe` | `http_probe` | Publish reusable HTTP endpoint facts. | `http_probe https://example.com/` | [http.probe](#httpprobe) |
| HTTP | `http.paths` | `http_paths` | Check explicit or common web paths. | `http_paths paths=/.git/config,/.env https://example.com/` | [http.paths](#httppaths) |
| HTTP | `http.repo_exposure` | `repo_exposure`, `git_expose_check` | Check for exposed repository metadata. | `http_probe https://example.com/ \| repo_exposure` | [http.repo_exposure](#httprepo_exposure) |
| HTTP | `http.webfin` | `webfin` (`web_fingerprint`) | Fingerprint web technologies. | `http_probe https://example.com/ \| webfin` | [http.webfin](#httpwebfin) |
| HTTP | `http.tls_probe` | `tls_probe` | Collect TLS certificate and hygiene facts. | `tls_probe https://example.com/` | [http.tls_probe](#httptls_probe) |
| HTTP | `http.waf_detect` | `waf_detect` | Detect likely WAF/CDN signals. | `waf_detect https://example.com/` | [http.waf_detect](#httpwaf_detect) |
| HTTP | `http.wafw00f` | `waf` | Wrap WafW00f and normalize WAF detections. | `http_probe https://example.com/ \| waf` | [http.wafw00f](#httpwafw00f) |
| HTTP | `http.nikto` | `nikto` | Wrap Nikto and normalize findings. | `http_probe https://example.com/ \| nikto` | [http.nikto](#httpnikto) |
| HTTP | `http.eyewitness` | `eyewitness` | Capture web screenshots through EyeWitness. | `http_probe https://example.com/ \| eyewitness` | [http.eyewitness](#httpeyewitness) |
| HTTP | `http.screenshotter` | `screenshotter` | Friendly EyeWitness-backed screenshot commandlet. | `http_probe https://example.com/ \| screenshotter` | [http.screenshotter](#httpscreenshotter) |
| Wireless | `wireless.wifi_scan` | `wifi_scan` | Wrap Kismet-style wireless scans. | `wifi_scan interface=wlan0mon duration=60` | [wireless.wifi_scan](#wirelesswifi_scan) |
| Analysis | `analysis.finding.dedupe` | `finding_dedupe` | Normalize and deduplicate findings. | `nikto https://example.com/ \| finding_dedupe` | [analysis.finding.dedupe](#analysisfindingdedupe) |
| Analysis | `analysis.finding.report` | `finding_report` | Render finding tables and report artifacts. | `finding_report export=findings.md` | [analysis.finding.report](#analysisfindingreport) |
| Analysis | `analysis.report` | `report` | Review, synthesize, accept, confirm, defer, or reject findings. | `http_probe https://example.test/ \| webfin \| report` | [analysis.report](#analysisreport) |
| Analysis | `analysis.finding` | `finding` | Lower-level finding review actions. | `finding confirm 1-3 pipeline=1` | [analysis.finding](#analysisfinding) |
| Analysis | `analysis.technology_indicators` | `technology_indicators`, `tech_review` | Promote passive vulnerable-version indicators. | `http_probe https://example.test/ \| webfin \| tech_review \| report` | [analysis.technology_indicators](#analysistechnology_indicators) |
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

## OS

### OS Plugin TOC

- [os.cat](#oscat)
- [os.less](#osless)
- [os.ls](#osls)


<a id="osls"></a>

### `os.ls`

Lists local files from inside the Bywaf interpreter.


Use this when you need quick local filesystem context without leaving the Bywaf
interpreter. It is intentionally read-only and console-oriented: it helps you inspect
paths before choosing plugins, manifests, output files, or artifacts to examine next.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | OS |
| Plugin | `os.ls` |
| Commandlets | `ls` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/os/ls.py bywaf/plugins/os/ls.plugin.toml` |

#### Commandlet: `ls`

Example usage: `ls bywaf/plugins`

Use `ls` to inspect local directories before opening files, importing artifacts, or
checking plugin paths. It prints a filesystem listing only; it does not create evidence
events or modify runtime state.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<path>` | No | Local path to list. | `bywaf/plugins` | Local path to list. |

- Visible output: prints a directory listing to the console.
- Emits: no event records; console output only.
- Intended use: quick filesystem inspection while staying in the same session.

[Back to OS plugin TOC](#os-plugin-toc) | [Back to document OS TOC entry](#toc-os)

<a id="oscat"></a>

### `os.cat`

Prints a local text file.


Use this for short text files where immediate inline output is more useful than opening
a pager. It is best for README snippets, manifests, small logs, and generated notes that
you want to inspect while staying in command flow.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | OS |
| Plugin | `os.cat` |
| Commandlets | `cat` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/os/cat.py bywaf/plugins/os/cat.plugin.toml` |

#### Commandlet: `cat`

Example usage: `cat README.md`

Use `cat` when you want the full contents of a small text file inline in the console.
For large files, prefer `less` so the output stays navigable.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<path>` | Yes | Local text file path. | `README.md` | Local text file path. |

- Visible output: prints the file contents to the console.
- Emits: no event records; console output only.
- Intended use: quick text inspection.

[Back to OS plugin TOC](#os-plugin-toc) | [Back to document OS TOC entry](#toc-os)

<a id="osless"></a>

### `os.less`

Opens the system pager for a local file when interactive.


Use this for longer local files where paging, searching, and scrolling are more
comfortable than dumping the whole file into the console. In non-interactive contexts it
produces a framework file-page request rather than pretending to emit scan evidence.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | OS |
| Plugin | `os.less` |
| Commandlets | `less` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/os/less.py bywaf/plugins/os/less.plugin.toml` |

#### Commandlet: `less`

Example usage: `less README.md`

Use `less` when the file is long enough that scrolling and search matter. It delegates
to the configured pager in interactive sessions and keeps the interpreter workflow
intact.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<path>` | Yes | Local file path. | `USAGE.md` | Local file path. |

- Visible output: opens the file in the configured pager.
- Emits: framework file-page request.
- Intended use: longer text inspection without leaving Bywaf.

[Back to OS plugin TOC](#os-plugin-toc) | [Back to document OS TOC entry](#toc-os)

## Discovery

### Discovery Plugin TOC

- [discovery.hostscanner](#discoveryhostscanner)

<a id="discoveryhostscanner"></a>

### `discovery.hostscanner`

Discovers live hosts with nmap and publishes reusable host facts.


Use this near the start of a network workflow to turn explicit ranges into stored host
facts. Those facts can feed later commandlets, which keeps pipelines reproducible and
avoids manually retyping target lists.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Discovery |
| Plugin | `discovery.hostscanner` |
| Commandlets | `hostscanner` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/discovery/hostscanner.py bywaf/plugins/discovery/hostscanner.plugin.toml` |

#### Commandlet: `hostscanner`

Example usage: `hostscanner 192.0.2.0/24`

Use `hostscanner` to discover live hosts from explicit hosts, ranges, or CIDR blocks. It
emits host and name facts that downstream commandlets can consume, and `--silent` is
useful when the event stream matters more than console alerts.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Host, range, or CIDR target. | `192.0.2.0/24` | Host, range, or CIDR target. |
| `host=` | No | Single explicit host, name, range, or CIDR. | `192.0.2.10` | Single explicit host, name, range, or CIDR. |
| `arguments=` | No | nmap host discovery arguments. | `-sn` | nmap host discovery arguments. |
| `except=` | No | Hosts or ranges to exclude. | `192.0.2.5` | Hosts or ranges to exclude. |
| `limit=` | No | Maximum live hosts to emit. | `256` | Maximum live hosts to emit. |
| `--silent` | No | Binary flag; suppress discovery alerts. | `--silent` | Binary flag; suppress discovery alerts. |

- Visible output: prints discovery alerts for live hosts unless `--silent` is
  set.
- Emits: `host.found`, `name.resolved`.
- External dependency: `nmap`.
- Intended use: first step in network pipelines.

[Back to Discovery plugin TOC](#discovery-plugin-toc) | [Back to document Discovery TOC entry](#toc-discovery)

## Network

### Network Plugin TOC

- [network.management_exposure](#networkmanagement_exposure)
- [network.portscanner](#networkportscanner)
- [network.service_probe](#networkservice_probe)
- [network.snmp_get](#networksnmp_get)
- [network.ssh_probe](#networkssh_probe)
- [network.tcp_banner](#networktcp_banner)
- [network.traceroute](#networktraceroute)

<a id="networkportscanner"></a>

### `network.portscanner`

Scans targets for open ports and renders stored open-port results.


Use this after targets are known to identify reachable TCP services and make the results
available to downstream network, HTTP, and reporting plugins. The plugin also provides a
read-side inventory view so operators can review open ports without rerunning scans.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.portscanner` |
| Commandlets | `portscanner`, `ports` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/portscanner bywaf/plugins/network/portscanner.plugin.toml` |

#### Commandlet: `portscanner`

Example usage: `portscanner port=22,80,443 host=192.0.2.10`

Use `portscanner` to turn host facts or explicit targets into `port.open` events. It can
run once over supplied targets or listen for upstream hosts, making it suitable for both
direct scans and discovery-driven pipelines.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<host>` | No | Positional host, range, or CIDR target. | `192.0.2.10` | Positional host, range, or CIDR target. |
| `host=` | No | Single explicit host to scan. | `192.0.2.10` | Single explicit host to scan. |
| `port=` | No | Comma/range port list; omit for nmap defaults. | `22,80,443` | Comma/range port list; omit for nmap defaults. |
| `ports=` | No | Compatibility alias for `port=`. | `1-1024` | Compatibility alias for `port=`. |
| `arguments=` | No | nmap port-scan arguments. | `-sT` | nmap port-scan arguments. |
| `except=` | No | Hosts to exclude from scans. | `192.0.2.5` | Hosts to exclude from scans. |
| `--listen` | No | Binary flag; poll scoped upstream `host.found` events. | `--listen` | Binary flag; poll scoped upstream `host.found` events. |
| `listen-interval=` | No | Poll interval in seconds. | `1.0` | Poll interval in seconds. |
| `listen-timeout=` | No | Seconds to listen; `0` means forever. | `30` | Seconds to listen; `0` means forever. |
| `--quiet` | No | Binary flag; suppress discovery alerts. | `--quiet` | Binary flag; suppress discovery alerts. |
| `--silent` | No | Binary flag; suppress discovery alerts. | `--silent` | Binary flag; suppress discovery alerts. |

- Consumes: `host.found`, `network.route.hop`.
- Visible output: prints open-port discovery alerts unless `--quiet` or
  `--silent` is set.
- Emits: `port.open`, selected `finding.candidate` events.
- External dependency: `nmap`.

#### Commandlet: `ports`

Example usage: `ports pipeline=1 --page`

Use `ports` to review stored open-port facts without scanning again. Selectors such as
`pipeline=`, `job=`, `host=`, and `port=` narrow the table to the part of the run you
care about.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `job=` | No | Job selector. | `latest` | Job selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `host=` | No | Host selector. | `192.0.2.10` | Host selector. |
| `port=` | No | Port selector. | `443` | Port selector. |
| `sort=` | No | Sort key. | `port` | Sort key. |
| `all=` | No | Include all rows. | `true` | Include all rows. |
| `--last` | No | Binary flag; show latest relevant scope. | `--last` | Binary flag; show latest relevant scope. |
| `--new` | No | Binary flag; show newly observed rows. | `--new` | Binary flag; show newly observed rows. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |

- Consumes: `port.open`.
- Visible output: prints or pages a table of stored open ports.
- Emits: no event records; console or paged output only.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networkservice_probe"></a>

### `network.service_probe`

Classifies services from existing open-port, banner, HTTP, or TLS facts.


Use this after port, banner, HTTP, or TLS facts exist and you want a normalized service
view. It is a passive classifier over existing facts, so it is useful between raw
discovery and higher-level exposure checks.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.service_probe` |
| Commandlets | `service_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/service_probe.py bywaf/plugins/network/service_probe.plugin.toml` |

#### Commandlet: `service_probe`

Example usage: `portscanner host=192.0.2.10 | service_probe`

Use `service_probe` after port or protocol facts exist to publish normalized service
labels. It is a lightweight classification pass that makes later exposure checks and
inventory views easier to read.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress service alerts. | `--silent` | Binary flag; suppress service alerts. |

- Consumes: `port.open`, `tcp.banner`, `http.endpoint`, `tls.certificate`.
- Visible output: prints detected-service alerts unless `--silent` is set.
- Emits: `service.detected`.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networktcp_banner"></a>

### `network.tcp_banner`

Connects to TCP services and records short banners.


Use this when the port number alone is not enough to identify what is listening. It
records small banners or HTTP HEAD responses as reusable facts that service
classification and exposure logic can consume later.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.tcp_banner` |
| Commandlets | `tcp_banner` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/tcp_banner.py bywaf/plugins/network/tcp_banner.plugin.toml` |

#### Commandlet: `tcp_banner`

Example usage: `tcp_banner mode=http-head 192.0.2.10:8080`

Use `tcp_banner` to collect a small protocol clue from a service. `mode=banner` reads a
basic banner, while `mode=http-head` asks HTTP-like services for headers without running
a full web workflow.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit `host[:port]` target. | `192.0.2.10:8080` | Explicit `host[:port]` target. |
| `mode=` | No | Probe mode: `banner` or `http-head`. | `http-head` | Probe mode: `banner` or `http-head`. |
| `port=` | No | Explicit port for bare host arguments. | `8080` | Explicit port for bare host arguments. |
| `read-bytes=` | No | Maximum bytes to read. | `256` | Maximum bytes to read. |
| `timeout=` | No | Connection and read timeout seconds. | `3` | Connection and read timeout seconds. |
| `--silent` | No | Binary flag; suppress banner alerts. | `--silent` | Binary flag; suppress banner alerts. |

- Consumes: `port.open`.
- Visible output: prints captured-banner alerts unless `--silent` is set.
- Emits: `tcp.banner`.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networkmanagement_exposure"></a>

### `network.management_exposure`

Promotes existing port, service, banner, endpoint, and fingerprint facts into
finding candidates for exposed management surfaces.


Use this when you already have network and web facts and want operator-facing finding
candidates for exposed administration or management surfaces. It does not authenticate,
brute force, exploit, or add new probes; it promotes existing evidence into reviewable
findings.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.management_exposure` |
| Commandlets | `management_exposure` |
| Last updated | `2026-06-03` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/management_exposure.py bywaf/plugins/network/management_exposure.plugin.toml` |

#### Commandlet: `management_exposure`

Example usage: `portscanner host=192.0.2.10 | service_probe | management_exposure`

Use `management_exposure` after discovery, service probing, banners, or web
fingerprinting to create candidate findings for admin and management surfaces. It reads
existing evidence only, so its output is a review queue item rather than proof of
exploitation.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress management exposure alerts. | `--silent` | Binary flag; suppress management exposure alerts. |

- Consumes: `port.open`, `service.detected`, `tcp.banner`, `http.endpoint`,
  `web.fingerprint`.
- Visible output: prints finding alerts for promoted management exposures unless
  `--silent` is set.
- Emits: `finding.candidate`.
- Safety boundary: passive only; no authentication, exploit, brute force, or
  added active probing.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networkssh_probe"></a>

### `network.ssh_probe`

Probes SSH service metadata and optional credential behavior.


Use this to record SSH service details and, when explicitly supplied, limited credential
behavior. Password input is declared secret-capable, so it should be handled through
Bywaf secret-aware paths rather than copied into notes or reports.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.ssh_probe` |
| Commandlets | `ssh_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/ssh_probe.py bywaf/plugins/network/ssh_probe.plugin.toml` |

#### Commandlet: `ssh_probe`

Example usage: `ssh_probe username=test password=test 192.0.2.10`

Use `ssh_probe` to record whether SSH is reachable and what authentication behavior is
observed from explicitly supplied credentials. Keep `password=` secret-aware, and use
timeouts to avoid blocking on unreachable hosts.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<host>` | No | SSH target host; upstream `port.open` may also supply targets. | `192.0.2.10` | SSH target host; upstream `port.open` may also supply targets. |
| `username=` | No | SSH username. | `test` | SSH username. |
| `password=` | No | SSH password; secret-capable. | `secret` | SSH password; secret-capable. |
| `port=` | No | SSH port. | `22` | SSH port. |
| `timeout=` | No | Connection timeout seconds. | `5` | Connection timeout seconds. |

- Consumes: `port.open`.
- Visible output: usually quiet on success; failures surface as command errors
  or tool-error events.
- Emits: `ssh.service`, `tool.error`.
- Secret handling: `password=` is declared as a secret option.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networksnmp_get"></a>

### `network.snmp_get`

Reads one SNMP OID from a target.


Use this for a targeted SNMP read when you know the host, community, and OID you want to
test. It is a focused probe, not a broad SNMP enumerator, and its value is in recording
one precise response or failure.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.snmp_get` |
| Commandlets | `snmp_get` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/snmp_get.py bywaf/plugins/network/snmp_get.plugin.toml` |

#### Commandlet: `snmp_get`

Example usage: `snmp_get community=public oid=1.3.6.1.2.1.1.1.0 192.0.2.10`

Use `snmp_get` for one precise SNMP question against a target. Successful reads become
`snmp.value` facts, while failures are retained as tool errors so the absence of a
response is still documented.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<host>` | Yes | SNMP target host. | `192.0.2.10` | SNMP target host. |
| `community=` | No | SNMP community string. | `public` | SNMP community string. |
| `oid=` | No | SNMP OID. | `1.3.6.1.2.1.1.1.0` | SNMP OID. |
| `port=` | No | SNMP UDP port. | `161` | SNMP UDP port. |
| `timeout=` | No | Timeout seconds. | `5` | Timeout seconds. |

- Visible output: usually quiet on success; failures surface as command errors
  or tool-error events.
- Emits: `snmp.value`, `tool.error`.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

<a id="networktraceroute"></a>

### `network.traceroute`

Records route hops to a target.


Use this to preserve route-hop context around a target or host discovered earlier in a
run. The emitted route facts can help explain network reachability, segmentation, and
where later scan results came from.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Network |
| Plugin | `network.traceroute` |
| Commandlets | `traceroute` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/network/traceroute.py bywaf/plugins/network/traceroute.plugin.toml` |

#### Commandlet: `traceroute`

Example usage: `traceroute 192.0.2.10`

Use `traceroute` to record hop paths for explicit targets or discovered hosts. The
results are useful context for segmentation, reachability, and explaining where scan
traffic traveled.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Host or address to trace. | `192.0.2.10` | Host or address to trace. |
| `binary=` | No | Traceroute executable. | `traceroute` | Traceroute executable. |
| `maxhops=` | No | Maximum hops. | `30` | Maximum hops. |
| `timeout=` | No | Per-hop wait time in seconds. | `5` | Per-hop wait time in seconds. |
| `--silent` | No | Binary flag; suppress per-target alerts. | `--silent` | Binary flag; suppress per-target alerts. |

- Consumes: `host.found`.
- Visible output: prints route-hop summary alerts unless `--silent` is set.
- Emits: `network.route.hop`, sometimes `host.found`, and `tool.error`.

[Back to Network plugin TOC](#network-plugin-toc) | [Back to document Network TOC entry](#toc-network)

## Recon

### Recon Plugin TOC

- [recon.dns_enum](#recondns_enum)
- [recon.dns_lookup](#recondns_lookup)
- [recon.shodan_lookup](#reconshodan_lookup)

<a id="recondns_lookup"></a>

### `recon.dns_lookup`

Resolves DNS records with dnspython.


Use this for a direct DNS question such as A, AAAA, MX, TXT, or NS resolution. It
records both successful records and DNS errors, making name-resolution assumptions
visible in the evidence stream.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Recon |
| Plugin | `recon.dns_lookup` |
| Commandlets | `dns_lookup` |
| Last updated | `2026-06-01` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/recon/dns_lookup/__init__.py bywaf/plugins/recon/dns_lookup/bywaf.plugin.toml` |

#### Commandlet: `dns_lookup`

Example usage: `dns_lookup record-type=MX example.com`

Use `dns_lookup` for direct record resolution and optional resolver selection. It is the
right commandlet when you already know the name and record type you want to verify.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<name>` | Yes | DNS name to resolve. | `example.com` | DNS name to resolve. |
| `record-type=` | No | DNS record type. | `MX` | DNS record type. |
| `resolver=` | No | Resolver IP address. | `1.1.1.1` | Resolver IP address. |
| `timeout=` | No | DNS timeout seconds. | `5` | DNS timeout seconds. |

- Visible output: usually quiet on success; DNS failures may appear as command
  errors or `dns.error` records.
- Emits: `dns.record`, `dns.error`, `tool.error`.

[Back to Recon plugin TOC](#recon-plugin-toc) | [Back to document Recon TOC entry](#toc-recon)

<a id="recondns_enum"></a>

### `recon.dns_enum`

Resolves explicit names or generated subdomains into host facts.


Use this to expand a base domain and a small word list into resolved names and host
facts. It is meant for lightweight starter enumeration that feeds network and HTTP
workflows rather than exhaustive DNS brute forcing.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Recon |
| Plugin | `recon.dns_enum` |
| Commandlets | `dns_enum` |
| Last updated | `2026-06-01` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/recon/dns_enum/__init__.py bywaf/plugins/recon/dns_enum/bywaf.plugin.toml` |

#### Commandlet: `dns_enum`

Example usage: `dns_enum domain=example.com words=www,api`

Use `dns_enum` to resolve explicit names or generated subdomains from `domain=` plus
`words=`. It emits both name and host facts so follow-on scanners can continue from
resolved addresses.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<name>` | No | DNS names to resolve. | `www.example.com` | DNS names to resolve. |
| `domain=` | No | Base domain for `words=`. | `example.com` | Base domain for `words=`. |
| `words=` | No | Comma or whitespace separated subdomain words. | `www,api,mail` | Comma or whitespace separated subdomain words. |
| `--silent` | No | Binary flag; suppress resolver alerts. | `--silent` | Binary flag; suppress resolver alerts. |

- Visible output: prints resolver alerts unless `--silent` is set.
- Emits: `name.resolved`, `host.found`, `dns.error`.

[Back to Recon plugin TOC](#recon-plugin-toc) | [Back to document Recon TOC entry](#toc-recon)

<a id="reconshodan_lookup"></a>

### `recon.shodan_lookup`

Queries Shodan by IP or search query.


Use this to enrich an IP or search query with Shodan data when an API key is available.
Treat it as third-party reconnaissance evidence: useful for context, but still something
to corroborate with direct Bywaf observations.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Recon |
| Plugin | `recon.shodan_lookup` |
| Commandlets | `shodan_lookup` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/recon/shodan_lookup.py bywaf/plugins/recon/shodan_lookup.plugin.toml` |

#### Commandlet: `shodan_lookup`

Example usage: `shodan_lookup mode=search apache country:US`

Use `shodan_lookup` in `host` mode for one IP or `search` mode for broader Shodan
queries. Supply the API key through the secret-capable option or environment and treat
results as enrichment to validate later.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<ip-or-query>` | Yes | IP address in host mode, or search terms in search mode. | `apache country:US` | IP address in host mode, or search terms in search mode. |
| `mode=` | No | Lookup mode: `host` or `search`. | `search` | Lookup mode: `host` or `search`. |
| `api-key=` | No | Shodan API key; secret-capable and defaults to `SHODAN_API_KEY`. | `shodan-api-key` | Shodan API key; secret-capable and defaults to `SHODAN_API_KEY`. |
| `limit=` | No | Maximum search results. | `10` | Maximum search results. |

- Visible output: usually quiet on success; lookup failures surface as command
  errors or tool-error events.
- Emits: `shodan.host`, `shodan.result`, `tool.error`.

[Back to Recon plugin TOC](#recon-plugin-toc) | [Back to document Recon TOC entry](#toc-recon)

## Identity

### Identity Plugin TOC

- [identity.ldap_probe](#identityldap_probe)
- [identity.smb_probe](#identitysmb_probe)

<a id="identityldap_probe"></a>

### `identity.ldap_probe`

Probes LDAP server metadata.


Use this to capture LDAP server metadata and basic bind behavior for identity
infrastructure. It is appropriate when domain controllers or directory services are in
scope and you need structured facts for later review.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Identity |
| Plugin | `identity.ldap_probe` |
| Commandlets | `ldap_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/identity/ldap_probe.py bywaf/plugins/identity/ldap_probe.plugin.toml` |

#### Commandlet: `ldap_probe`

Example usage: `ldap_probe username=user password=secret dc.example.test`

Use `ldap_probe` to capture LDAP server metadata and optional bind results. The
commandlet is useful for directory-service context, and `password=` is secret-capable
for credentialed probes.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<host>` | Yes | LDAP target host. | `dc.example.test` | LDAP target host. |
| `username=` | No | LDAP username. | `user` | LDAP username. |
| `password=` | No | LDAP password; secret-capable. | `secret` | LDAP password; secret-capable. |
| `base-dn=` | No | Optional LDAP search base. | `dc=example,dc=test` | Optional LDAP search base. |
| `port=` | No | LDAP port. | `389` | LDAP port. |
| `ssl=` | No | Use LDAPS: `true` or `false`. | `true` | Use LDAPS: `true` or `false`. |
| `timeout=` | No | Connection timeout seconds. | `5` | Connection timeout seconds. |

- Visible output: usually quiet on success; connection or bind problems surface
  as command errors or tool-error events.
- Emits: `ldap.server`, `tool.error`.

[Back to Identity plugin TOC](#identity-plugin-toc) | [Back to document Identity TOC entry](#toc-identity)

<a id="identitysmb_probe"></a>

### `identity.smb_probe`

Probes SMB server metadata.


Use this to record SMB server metadata and basic authentication behavior. It helps
distinguish Windows file-sharing and domain services from generic open ports while
preserving errors as tool facts.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Identity |
| Plugin | `identity.smb_probe` |
| Commandlets | `smb_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/identity/smb_probe.py bywaf/plugins/identity/smb_probe.plugin.toml` |

#### Commandlet: `smb_probe`

Example usage: `smb_probe domain=EXAMPLE username=user password=secret dc.example.test`

Use `smb_probe` to capture SMB metadata and optional authentication behavior. Domain,
username, and password arguments let you distinguish anonymous, guest, and
supplied-credential outcomes when they are in scope.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<host>` | Yes | SMB target host. | `dc.example.test` | SMB target host. |
| `domain=` | No | SMB domain. | `EXAMPLE` | SMB domain. |
| `username=` | No | SMB username. | `user` | SMB username. |
| `password=` | No | SMB password; secret-capable. | `secret` | SMB password; secret-capable. |
| `port=` | No | SMB port. | `445` | SMB port. |
| `timeout=` | No | Connection timeout seconds. | `5` | Connection timeout seconds. |

- Visible output: usually quiet on success; connection or auth problems surface
  as command errors or tool-error events.
- Emits: `smb.server`, `tool.error`.

[Back to Identity plugin TOC](#identity-plugin-toc) | [Back to document Identity TOC entry](#toc-identity)

## HTTP

### HTTP Plugin TOC

- [http.eyewitness](#httpeyewitness)
- [http.auth](#httpauth)
- [http.cors](#httpcors)
- [http.headers](#httpheaders)
- [http.methods](#httpmethods)
- [http.paths](#httppaths)
- [http.probe](#httpprobe)
- [http.nikto](#httpnikto)
- [http.repo_exposure](#httprepo_exposure)
- [http.screenshotter](#httpscreenshotter)
- [http.tls_probe](#httptls_probe)
- [http.waf_detect](#httpwaf_detect)
- [http.wafw00f](#httpwafw00f)
- [http.webfin](#httpwebfin)

<a id="httpheaders"></a>

### `http.headers`

Collects HTTP response headers and promotes missing high-value security headers.


Use this when header posture matters: it records response headers and promotes missing
high-value security headers into finding candidates. It is a small HTTP probe that pairs
well with `http_probe` and report review.
Current finding coverage includes missing HSTS, missing X-Content-Type-Options,
missing Content-Security-Policy, missing Referrer-Policy, missing browser framing
protection, weak cookie attributes, implementation-disclosing Server headers, and
HTTPS-to-HTTP redirects.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.headers` |
| Commandlets | `http_headers` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/headers bywaf/plugins/http/headers/bywaf.plugin.toml` |

#### Commandlet: `http_headers`

Example usage: `http_headers ssl=true example.com`

Use `http_headers` to collect response headers and promote missing security-header
findings. It can use explicit targets or upstream open ports, and successful findings
are reviewed through `report` or `finding_report`.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Target host; upstream `port.open` may also supply targets. | `example.com` | Target host; upstream `port.open` may also supply targets. |
| `port=` | No | Target port. | `443` | Target port. |
| `ssl=` | No | Use HTTPS: `true` or `false`. | `true` | Use HTTPS: `true` or `false`. |
| `timeout=` | No | Connection timeout seconds. | `5` | Connection timeout seconds. |

- Consumes: `port.open`.
- Visible output: usually quiet on success; reportable missing-header issues are
  visible through `report` or `finding_report`.
- Emits: `http.headers`, `finding.candidate`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpauth"></a>

### `http.auth`

Probes HTTP authentication challenges and reports passive auth posture findings.


Use this when authentication exposure matters: it records WWW-Authenticate and
Proxy-Authenticate challenge metadata and promotes conservative posture findings.
It is a small passive HTTP probe that pairs well with `http_probe`,
`http_headers`, `http_methods`, and report review.
Current finding coverage includes Basic authentication offered over cleartext
HTTP, authentication challenges on administrative-looking paths, and Basic
authentication challenges with no realm value.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.auth` |
| Commandlets | `http_auth` |
| Last updated | `2026-06-06` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/auth` |

#### Commandlet: `http_auth`

Example usage: `http_auth https://example.com/admin`

Use `http_auth` to collect HTTP authentication challenge posture and promote
safe auth-posture findings. It can use explicit URLs, hosts, host:port targets,
or upstream open ports, and successful findings are reviewed through `report`
or `finding_report`.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | URL, host, host:port, or upstream `port.open` target. | `https://example.com/admin` | URL, host, host:port, or upstream `port.open` target. |
| `path=` | No | Request path. | `/admin` | Request path. |
| `scheme=` | No | Scheme override: `auto`, `http`, or `https`. | `https` | Scheme override: `auto`, `http`, or `https`. |
| `method=` | No | HTTP method: `HEAD` or `GET`. | `HEAD` | HTTP method. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |

- Consumes: `port.open`.
- Visible output: usually quiet on success; reportable auth-posture issues are
  visible through `report` or `finding_report`.
- Emits: `http.auth`, `finding.candidate`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpcors"></a>

### `http.cors`

Probes HTTP CORS posture and reports unsafe cross-origin policy candidates.


Use this when browser cross-origin policy matters: it sends one bounded
preflight-style request with a synthetic `Origin` header, records CORS response
headers, and promotes only clear unsafe posture candidates. It pairs well with
`http_probe`, `http_headers`, `http_methods`, and report review.
Current finding coverage includes arbitrary Origin reflection, arbitrary Origin
reflection with credentials, and wildcard Origin with credentials.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.cors` |
| Commandlets | `http_cors` |
| Last updated | `2026-06-07` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/cors` |

#### Commandlet: `http_cors`

Example usage: `http_cors https://example.com/api origin=https://evil.example`

Use `http_cors` to collect CORS response posture and promote safe
CORS-posture findings. It can use explicit URLs, hosts, host:port targets, or
upstream open ports, and successful findings are reviewed through `report` or
`finding_report`.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | URL, host, host:port, or upstream `port.open` target. | `https://example.com/api` | URL, host, host:port, or upstream `port.open` target. |
| `origin=` | No | Origin header value. | `https://evil.example` | Origin header value. |
| `path=` | No | Request path. | `/api` | Request path. |
| `request-method=` | No | CORS requested method: `GET`, `POST`, `PUT`, `DELETE`, or `PATCH`. | `GET` | Access-Control-Request-Method value. |
| `scheme=` | No | Scheme override: `auto`, `http`, or `https`. | `https` | Scheme override: `auto`, `http`, or `https`. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |

- Consumes: `port.open`.
- Visible output: usually quiet on success; reportable CORS-posture issues are
  visible through `report` or `finding_report`.
- Emits: `http.cors`, `finding.candidate`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpmethods"></a>

### `http.methods`

Probes HTTP OPTIONS and reports risky allowed methods.


Use this when method posture matters: it records the methods advertised by
`Allow` or `Public` response headers and promotes risky methods into finding
candidates. It is a small HTTP probe that pairs well with `http_probe`,
`http_headers`, and report review.
Current finding coverage includes enabled TRACE, write-capable methods such as
PUT, PATCH, and DELETE, and WebDAV methods such as PROPFIND or MKCOL.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.methods` |
| Commandlets | `http_methods` |
| Last updated | `2026-06-06` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/methods` |

#### Commandlet: `http_methods`

Example usage: `http_methods https://example.com/`

Use `http_methods` to collect HTTP method posture and promote risky method
findings. It can use explicit URLs, hosts, host:port targets, or upstream open
ports, and successful findings are reviewed through `report` or
`finding_report`.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | URL, host, host:port, or upstream `port.open` target. | `https://example.com/` | URL, host, host:port, or upstream `port.open` target. |
| `path=` | No | Request path. | `/admin` | Request path. |
| `scheme=` | No | Scheme override: `auto`, `http`, or `https`. | `https` | Scheme override: `auto`, `http`, or `https`. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |
| `--silent` | No | Binary flag; suppress method alerts. | `--silent` | Binary flag; suppress method alerts. |

- Consumes: `port.open`.
- Visible output: prints method alerts unless `--silent` is set; reportable
  risky-method issues are visible through `report` or `finding_report`.
- Emits: `http.methods`, `finding.candidate`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpprobe"></a>

### `http.probe`

Probes HTTP endpoints and publishes reusable endpoint facts.


Use this to establish canonical HTTP endpoint facts before running web fingerprinting,
path checks, screenshots, Nikto, or WAF detection. It normalizes URLs, schemes, status
codes, and redirect behavior into facts that downstream plugins share.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.probe` |
| Commandlets | `http_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/probe bywaf/plugins/http/probe/bywaf.plugin.toml` |

#### Commandlet: `http_probe`

Example usage: `http_probe https://example.com/`

Use `http_probe` to create normalized endpoint facts from URLs, hosts, or upstream
ports. Downstream web commandlets rely on these facts, so this is often the first HTTP
step in a pipeline.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | URL, host, or upstream `port.open` target. | `https://example.com/` | URL, host, or upstream `port.open` target. |
| `scheme=` | No | Scheme override: `auto`, `http`, or `https`. | `https` | Scheme override: `auto`, `http`, or `https`. |
| `path=` | No | Request path. | `/login` | Request path. |
| `method=` | No | HTTP method: `HEAD` or `GET`. | `GET` | HTTP method: `HEAD` or `GET`. |
| `follow-redirects=` | No | Follow redirects: `true` or `false`. | `true` | Follow redirects: `true` or `false`. |
| `cookie-file=` | No | Netscape-format cookie file. | `cookies.txt` | Netscape-format cookie file. |
| `firefox-profile=` | No | Firefox profile directory or `cookies.sqlite`. | `~/.mozilla/firefox/profile` | Firefox profile directory or `cookies.sqlite`. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` | HTTP User-Agent. |
| `--silent` | No | Binary flag; suppress probe alerts. | `--silent` | Binary flag; suppress probe alerts. |

- Consumes: `port.open`.
- Visible output: prints probe alerts unless `--silent` is set.
- Emits: `http.endpoint`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httppaths"></a>

### `http.paths`

Checks common or explicitly supplied HTTP paths.


Use this to check a focused list of sensitive paths or Bywaf's built-in common paths
against known HTTP endpoints. It records each checked path and promotes only
operator-relevant exposures into finding candidates.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.paths` |
| Commandlets | `http_paths` |
| Last updated | `2026-06-03` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/paths bywaf/plugins/http/paths/findings.py bywaf/plugins/http/paths/bywaf.plugin.toml` |

#### Commandlet: `http_paths`

Example usage: `http_paths paths=/.git/config,/.env https://example.com/`

Use `http_paths` to check explicit paths or default sensitive paths against known
endpoints. It records every path check and promotes exposed config, repository, backup,
admin, and environment surfaces into reviewable findings.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<url>` | No | Explicit base URL or host. | `https://example.com/` | Explicit base URL or host. |
| `paths=` | No | Comma or whitespace separated paths. | `/.git/config,/.env` | Comma or whitespace separated paths. |
| `timeout=` | No | HTTP timeout seconds. | `5` | HTTP timeout seconds. |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` | HTTP User-Agent. |
| `--silent` | No | Binary flag; suppress path alerts. | `--silent` | Binary flag; suppress path alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints checked-path alerts unless `--silent` is set; promoted
  findings are visible through `report` or `finding_report`.
- Emits: `http.path`, `finding.candidate`.
- Findings: exposed `.git/config`, source maps, dependency metadata, cloud/app
  config files, sensitive config files, backup archives, database dumps, admin
  login surfaces, and selected environment endpoints.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httprepo_exposure"></a>

### `http.repo_exposure`

Checks HTTP endpoints for exposed repository metadata.


Use this when repository metadata exposure is the specific question. It is narrower than
`http_paths`, focused on exposed Git configuration, and exists for pipelines that want
that check and finding type explicitly.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.repo_exposure` |
| Commandlets | `repo_exposure`, `git_expose_check` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/repo_exposure bywaf/plugins/http/repo_exposure/bywaf.plugin.toml` |

#### Commandlets: `repo_exposure`, `git_expose_check`

Example usage: `http_probe https://example.com/ | repo_exposure`

Use `repo_exposure` or `git_expose_check` when exposed Git metadata is the specific
concern. The commandlet checks endpoint-derived or explicit URLs and emits both
checked-path evidence and `web.exposure.git_config` finding candidates.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `target=` | No | Explicit URL or host selector. | `https://example.com/` | Explicit URL or host selector. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` | HTTP User-Agent. |
| `--silent` | No | Binary flag; suppress exposure alerts. | `--silent` | Binary flag; suppress exposure alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints exposed `.git/config` alerts unless `--silent` is set.
- Emits: `repo.git_config.checked`, `finding.candidate`.
- Findings: `web.exposure.git_config`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpwebfin"></a>

### `http.webfin`

Fingerprints web technologies from HTTP endpoints.


Use this to fingerprint web technologies from endpoint responses. The resulting web
facts help operators understand likely frameworks and can steer later checks such as
Nikto source selection or management exposure review.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.webfin` |
| Commandlets | `webfin` |
| Aliases | `web_fingerprint` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/webfin.py bywaf/plugins/http/webfin.plugin.toml` |

#### Commandlet: `webfin`

Example usage: `http_probe https://example.com/ | webfin`

Use `webfin` after `http_probe` to identify likely web stacks from response behavior.
The fingerprints help prioritize later checks and provide context in inventory and
reports. `web_fingerprint` is a descriptive alias for the same commandlet; runtime
and audit records use the canonical `webfin` name.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `timeout=` | No | Request timeout seconds. | `5` | Request timeout seconds. |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` | HTTP User-Agent. |
| `--silent` | No | Binary flag; suppress fingerprint alerts. | `--silent` | Binary flag; suppress fingerprint alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints fingerprint alerts unless `--silent` is set.
- Emits: `web.fingerprint`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httptls_probe"></a>

### `http.tls_probe`

Collects TLS certificate and hygiene facts.


Use this to capture certificate details and TLS hygiene signals for HTTPS services. It
turns certificate state into facts and findings, which makes expired or mismatched
certificates visible in normal report workflows.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.tls_probe` |
| Commandlets | `tls_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/tls_probe/` |

#### Commandlet: `tls_probe`

Example usage: `tls_probe https://example.com/`

Use `tls_probe` to record certificate details for HTTPS targets and upstream TLS-capable
endpoints. It promotes expired certificates and hostname mismatches into findings while
retaining certificate facts for inventory.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit `host[:port]` or HTTPS URL target. | `example.com:443` | Explicit `host[:port]` or HTTPS URL target. |
| `port=` | No | Default TLS port for bare hosts. | `443` | Default TLS port for bare hosts. |
| `timeout=` | No | Connection timeout seconds. | `5` | Connection timeout seconds. |
| `--silent` | No | Binary flag; suppress TLS alerts. | `--silent` | Binary flag; suppress TLS alerts. |

- Consumes: `port.open`, `http.endpoint`.
- Visible output: prints TLS capture alerts unless `--silent` is set; promoted
  findings are visible through `report` or `finding_report`.
- Emits: `tls.certificate`, `tls.probe.error`, `finding.candidate`.
- Findings: expired certificates and hostname mismatches.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpwaf_detect"></a>

### `http.waf_detect`

Detects likely web application firewall or CDN response signals.


Use this to identify likely WAF, CDN, or protective gateway signals from HTTP responses.
The output is contextual rather than a vulnerability by itself, and it helps explain
later scan behavior or filtering.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.waf_detect` |
| Commandlets | `waf_detect` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/waf_detect.py bywaf/plugins/http/waf_detect.plugin.toml` |

#### Commandlet: `waf_detect`

Example usage: `waf_detect https://example.com/`

Use `waf_detect` to capture WAF or CDN indicators from HTTP responses. Its output helps
interpret blocked scans, unusual status codes, and protected paths without treating
protection itself as a vulnerability.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `timeout=` | No | HTTP timeout seconds. | `5` | HTTP timeout seconds. |
| `user-agent=` | No | HTTP User-Agent. | `Bywaf/0.12` | HTTP User-Agent. |
| `--silent` | No | Binary flag; suppress WAF alerts. | `--silent` | Binary flag; suppress WAF alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints WAF detection alerts unless `--silent` is set.
- Emits: `web.waf.detected`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpwafw00f"></a>

### `http.wafw00f`

Runs WafW00f through the framework process API and normalizes WAF detections.


Use this when you want WafW00f's active WAF fingerprinting while preserving Bywaf
process provenance, raw stdout/stderr artifacts, and shared `web.waf.detected`
events. It complements `waf_detect`: `waf_detect` is the built-in passive header
heuristic, while `waf` delegates to the external WafW00f tool.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.wafw00f` |
| Commandlets | `waf` |
| Last updated | `2026-06-11` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/wafw00f/` |

#### Commandlet: `waf`

Example usage: `http_probe https://example.com/ | waf`

Use `waf` against explicit URLs or upstream `http.endpoint` events. The commandlet
launches WafW00f through the framework process service, which records stdout/stderr
as process transcript artifacts, then publishes normalized WAF detections for
inventory and reporting.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit HTTP or HTTPS URL. | `https://example.com/` | Explicit target; upstream `http.endpoint` may also supply targets. |
| `binary=` | No | WafW00f executable. | `wafw00f` | External WafW00f command or path. |
| `timeout=` | No | Seconds per target. | `90` | Maximum process runtime for each target. |
| `--silent` | No | Binary flag; suppress WAF alerts. | `--silent` | Binary flag; suppress WAF alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints WAF detection alerts unless `--silent` is set and
  attaches raw WafW00f stdout/stderr process artifacts through the framework.
- Emits: `web.waf.detected`, `tool.error`.
- External dependency: `wafw00f`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpnikto"></a>

### `http.nikto`

Runs Nikto through the framework process API and normalizes selected output.


Use this to run Nikto through Bywaf while preserving raw tool output and normalizing
selected issues into findings. It is useful when you want a familiar external scanner
but still need Bywaf provenance, artifacts, and report integration.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.nikto` |
| Commandlets | `nikto` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/nikto/` |

#### Commandlet: `nikto`

Example usage: `http_probe https://example.com/ | nikto`

Use `nikto` when you want Nikto coverage but need Bywaf artifacts, events, and finding
normalization. It can consume endpoint facts, attach raw output, and emit vulnerability
and finding topics for later dedupe and review.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `binary=` | No | Nikto executable. | `nikto` | Nikto executable. |
| `plugins=` | No | Nikto plugin selector. | `@@DEFAULT` | Nikto plugin selector. |
| `source=` | No | Endpoint source: `all`, `explicit`, or `webfin`. | `webfin` | Endpoint source: `all`, `explicit`, or `webfin`. |
| `timeout=` | No | Seconds per target. | `300` | Seconds per target. |
| `tuning=` | No | Nikto tuning selector. | `x` | Nikto tuning selector. |
| `--silent` | No | Binary flag; suppress finding alerts. | `--silent` | Binary flag; suppress finding alerts. |

- Consumes: `http.endpoint`, `web.fingerprint`.
- Visible output: prints finding alerts unless `--silent` is set and attaches
  raw Nikto output artifacts when available.
- Emits: `nikto.finding`, `vulnerability.found`,
  `vulnerability.potential`, artifacts for raw output.
- External dependency: `nikto`.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpeyewitness"></a>

### `http.eyewitness`

Wraps EyeWitness to capture web screenshots.


Use this when visual evidence matters, especially for validating live web applications
and documenting exposed login pages or consoles. It wraps EyeWitness while attaching
screenshots and raw tool output as artifacts.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.eyewitness` |
| Commandlets | `eyewitness` |
| Last updated | `2026-06-03` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/eyewitness.py bywaf/plugins/http/eyewitness.plugin.toml` |

#### Commandlet: `eyewitness`

Example usage: `http_probe https://example.com/ | eyewitness`

Use `eyewitness` to capture screenshots from explicit or endpoint-derived web targets.
It writes visual evidence and raw tool output as artifacts, making screenshots available
for reports and handoff bundles.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `binary=` | No | EyeWitness executable. | `eyewitness` | EyeWitness executable. |
| `output-dir=` | No | Directory for EyeWitness output. | `artifacts/eyewitness` | Directory for EyeWitness output. |
| `source=` | No | Endpoint source: `all` or `explicit`. | `all` | Endpoint source: `all` or `explicit`. |
| `timeout=` | No | Seconds for the EyeWitness run. | `600` | Seconds for the EyeWitness run. |
| `--silent` | No | Binary flag; suppress screenshot alerts. | `--silent` | Binary flag; suppress screenshot alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints screenshot alerts unless `--silent` is set and attaches
  screenshot artifacts when files are produced.
- Emits: `eyewitness.screenshot`, `web.screenshotted_host`, screenshot
  artifacts and raw tool output artifacts.
- External dependency: EyeWitness.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

<a id="httpscreenshotter"></a>

### `http.screenshotter`

Friendly Bywaf commandlet name for the same EyeWitness screenshot workflow.


Use this as the friendly Bywaf-facing screenshot command for the EyeWitness workflow. It
is aimed at operators who want screenshots and attached artifacts without remembering
the external tool name.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.screenshotter` |
| Commandlets | `screenshotter` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/screenshotter.py bywaf/plugins/http/screenshotter.plugin.toml` |

#### Commandlet: `screenshotter`

Example usage: `http_probe https://example.com/ | screenshotter`

Use `screenshotter` for the same screenshot workflow through a Bywaf-native name. It is
convenient in operator pipelines where the intent is visual capture rather than invoking
EyeWitness by name.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | No | Explicit URL or host. | `https://example.com/` | Explicit URL or host. |
| `binary=` | No | EyeWitness executable. | `eyewitness` | EyeWitness executable. |
| `output-dir=` | No | Directory for EyeWitness output. | `artifacts/screenshots` | Directory for EyeWitness output. |
| `source=` | No | Endpoint source: `all` or `explicit`. | `all` | Endpoint source: `all` or `explicit`. |
| `timeout=` | No | Seconds for the EyeWitness run. | `600` | Seconds for the EyeWitness run. |
| `--silent` | No | Binary flag; suppress screenshot alerts. | `--silent` | Binary flag; suppress screenshot alerts. |

- Consumes: `http.endpoint`.
- Visible output: prints screenshot alerts unless `--silent` is set and attaches
  screenshot artifacts when files are produced.
- Emits: `eyewitness.screenshot`, `web.screenshotted_host`, screenshot
  artifacts and raw tool output artifacts.
- External dependency: EyeWitness.

[Back to HTTP plugin TOC](#http-plugin-toc) | [Back to document HTTP TOC entry](#toc-http)

## Wireless

### Wireless Plugin TOC

- [wireless.wifi_scan](#wirelesswifi_scan)

<a id="wirelesswifi_scan"></a>

### `wireless.wifi_scan`

Wraps Kismet-style wireless scanning and stores produced logs.


Use this for in-scope wireless collection through Kismet-compatible tooling. The plugin
stores discovered network facts and attaches produced logs so wireless evidence can
travel with the rest of the assessment record.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Wireless |
| Plugin | `wireless.wifi_scan` |
| Commandlets | `wifi_scan` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/wireless/wifi_scan.py bywaf/plugins/wireless/wifi_scan.plugin.toml` |

#### Commandlet: `wifi_scan`

Example usage: `wifi_scan interface=wlan0mon duration=60`

Use `wifi_scan` to run a bounded Kismet-compatible capture on a specific interface. The
duration, log types, and output directory determine what evidence is produced and
attached.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `interface=` | Yes | Wireless capture interface. | `wlan0mon` | Wireless capture interface. |
| `binary=` | No | Kismet executable. | `kismet` | Kismet executable. |
| `duration=` | No | Scan duration seconds. | `60` | Scan duration seconds. |
| `log-types=` | No | Kismet log types. | `kismet,json` | Kismet log types. |
| `output-dir=` | No | Directory for Kismet output. | `artifacts/wifi` | Directory for Kismet output. |
| `--silent` | No | Binary flag; suppress network alerts. | `--silent` | Binary flag; suppress network alerts. |

- Visible output: prints wireless-network alerts unless `--silent` is set and
  attaches produced Kismet logs.
- Emits: `wifi.network`, `kismet.network`, artifacts for produced logs.
- External dependency: Kismet-compatible tooling.

[Back to Wireless plugin TOC](#wireless-plugin-toc) | [Back to document Wireless TOC entry](#toc-wireless)

## Analysis

### Analysis Plugin TOC

- [analysis.finding](#analysisfinding)
- [analysis.finding.dedupe](#analysisfindingdedupe)
- [analysis.finding.report](#analysisfindingreport)
- [analysis.report](#analysisreport)
- [analysis.technology_indicators](#analysistechnology_indicators)
- [analysis.yara_scan](#analysisyara_scan)

<a id="analysisfindingdedupe"></a>

### `analysis.finding.dedupe`

Normalizes and deduplicates raw finding streams.


Use this after scanners or finding-producing plugins have emitted raw candidates and you
want a cleaner inbox. It normalizes titles and identities, collapses duplicates, and
flags merge candidates for operator review.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.finding.dedupe` |
| Commandlets | `finding_dedupe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/finding/dedupe/__init__.py bywaf/plugins/analysis/finding/dedupe/bywaf.plugin.toml` |

#### Commandlet: `finding_dedupe`

Example usage: `nikto https://example.com/ | finding_dedupe`

Use `finding_dedupe` to clean up finding streams before review or export. It emits new,
duplicate, updated, and merge-candidate lifecycle events so the report inbox can focus
on distinct issues.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `file=` | No | Write and attach a JSON or Markdown dedupe summary. | `dedupe-summary.json` | Write and attach a JSON or Markdown dedupe summary. |
| `format=` | No | Summary format: `json` or `md`. | `md` | Summary format: `json` or `md`. |
| `limit=` | No | Maximum historical input events when no pipeline input exists. | `1000` | Maximum historical input events when no pipeline input exists. |
| `threshold=` | No | Minimum fuzzy score for merge candidates. | `0.82` | Minimum fuzzy score for merge candidates. |
| `--silent` | No | Binary flag; suppress finding alerts. | `--silent` | Binary flag; suppress finding alerts. |

- Consumes: `finding.candidate`, `finding.confirmed`, Nikto and vulnerability
  topics.
- Visible output: prints a dedupe summary line and optional finding alerts
  unless `--silent` is set; attaches a summary artifact when `file=` is used.
- Emits: `finding.new`, `finding.duplicate`, `finding.updated`,
  `finding.merge_candidate`.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysisfindingreport"></a>

### `analysis.finding.report`

Renders finding tables and exports report artifacts.


Use this when you need a rendered finding table or exported report artifact from stored
findings. It is a report-generation commandlet rather than an inbox: use `report` when
you need to accept, defer, or reject rows interactively.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.finding.report` |
| Commandlets | `finding_report` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/finding/report/__init__.py bywaf/plugins/analysis/finding/report/bywaf.plugin.toml` |

#### Commandlet: `finding_report`

Example usage: `finding_report export=findings.md`

Use `finding_report` to render findings as a table or export them to a file artifact. It
is best after dedupe or review when you need a shareable snapshot rather than an
interactive inbox.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `source=` | No | Finding source: `auto`, `dedupe`, `tools`, or `all`. | `dedupe` | Finding source: `auto`, `dedupe`, `tools`, or `all`. |
| `export=` | No | Write and attach a table file; format inferred from suffix. | `findings.md` | Write and attach a table file; format inferred from suffix. |
| `file=` | No | Compatibility alias for `export=`. | `findings.xlsx` | Compatibility alias for `export=`. |
| `format=` | No | File format when suffix is ambiguous. | `md` | File format when suffix is ambiguous. |
| `limit=` | No | Maximum events to inspect when no pipeline input exists. | `1000` | Maximum events to inspect when no pipeline input exists. |
| `--candidates` | No | Binary flag; include merge candidates. | `--candidates` | Binary flag; include merge candidates. |

- Consumes: finding and vulnerability topics.
- Visible output: renders a findings table and writes/attaches an exported
  report artifact when `export=` or `file=` is used.
- Emits: table render requests and report artifacts when exported.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysisreport"></a>

### `analysis.report`

Operator finding inbox for reviewing and scoping report findings.


Use this as the main operator-facing finding inbox. It supports scoped review,
safe passive synthesis over existing facts, compact summaries, detailed rows,
and lifecycle decisions such as accept, defer, reject, confirm, or unconfirm.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.report` |
| Commandlets | `report` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/report bywaf/plugins/analysis/report.plugin.toml` |

#### Commandlet: `report`

Example usage: `http_probe https://example.test/ | webfin | report`

Use `report` to view scoped findings and make review decisions. Actions such as
`accept`, `defer`, and `reject` create review events, while `network`, `show`, and
`detail` help inspect context before deciding. By default, normal report renders
run safe passive analysis over already-collected service, banner, endpoint, and
fingerprint facts before rendering; use `analyze=off` for a pure snapshot.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | No | `network`, `detail`, `accept`, `confirm`, `defer`, `reject`, `unconfirm`, `create`, `show`, or `update`. | `accept` | `network`, `detail`, `accept`, `confirm`, `defer`, `reject`, `unconfirm`, `create`, `show`, or `update`. |
| `<selection>` | No | Row index, range, or `all` for detail/review actions. | `1-3,7` | Row index, range, or `all` for detail/review actions. |
| `pipeline=` | No | Pipeline id or comma-separated ids. | `1,2` | Pipeline id or comma-separated ids. |
| `job=` | No | Job id or comma-separated ids. | `7` | Job id or comma-separated ids. |
| `step=` | No | Step id or comma-separated ids. | `12` | Step id or comma-separated ids. |
| `name=` | No | Saved report scope name. | `quarterly` | Saved report scope name. |
| `limit=` | No | Maximum events to inspect. | `1000` | Maximum events to inspect. |
| `note=` | No | Operator review note; consumes the rest of the line. | `validated manually` | Operator review note; consumes the rest of the line. |
| `analyze=` | No | Passive synthesis mode: `passive` or `off`. | `passive` | Run safe passive analysis over selected facts before rendering. |
| `page=` | No | Page rendered report output: `true` or `false`. | `false` | Page rendered report output: `true` or `false`. |
| `sort=` | No | Group report rows by `finding` or `host`. | `host` | Group report rows by `finding` or `host`. |
| `status=` | No | Review status filter. | `open` | Review status filter. |
| `--last` | No | Binary flag; show latest scan/reportable pipeline. | `--last` | Binary flag; show latest scan/reportable pipeline. |
| `--new` | No | Binary flag; show newly introduced facts. | `--new` | Binary flag; show newly introduced facts. |
| `--accepted-first` | No | Binary flag; show accepted findings before other states. | `--accepted-first` | Binary flag; show accepted findings before other states. |
| `--candidates-first` | No | Binary flag; show candidate or potential findings first. | `--candidates-first` | Binary flag; show candidate or potential findings first. |

- Consumes: finding lifecycle topics plus report context facts, including
  service, banner, HTTP endpoint, and web fingerprint facts used for passive
  synthesis.
- Visible output: renders a compact finding inbox, detailed finding views, or
  network summary tables; review actions print action results/errors.
- Emits: `report.rendered`, `report.scope.saved`, `finding.reviewed`, and
  synthesized finding candidate/dedupe events when `analyze=passive`.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysisfinding"></a>

### `analysis.finding`

Lower-level commandlet for confirming or unconfirming finding rows.


Use this lower-level command when you only need to mark finding rows confirmed or
unconfirmed. Most day-to-day review should use `report`; this commandlet remains useful
for direct lifecycle edits and compatibility.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.finding` |
| Commandlets | `finding` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/finding.py bywaf/plugins/analysis/finding.plugin.toml` |

#### Commandlet: `finding`

Example usage: `finding confirm 1-3 pipeline=1`

Use `finding` for direct confirm or unconfirm operations against numbered rows. It
shares row-selection behavior with report views but intentionally exposes only the
narrow confirmation workflow.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | Finding action: `confirm` or `unconfirm`. | `confirm` | Finding action: `confirm` or `unconfirm`. |
| `<selection>` | Yes | Row index range or `all`. | `1-3` | Row index range or `all`. |
| `pipeline=` | No | Pipeline id or comma-separated ids. | `1` | Pipeline id or comma-separated ids. |
| `job=` | No | Job id or comma-separated ids. | `7` | Job id or comma-separated ids. |
| `step=` | No | Step id or comma-separated ids. | `12` | Step id or comma-separated ids. |
| `limit=` | No | Maximum events to inspect. | `1000` | Maximum events to inspect. |
| `note=` | No | Operator review note. | `validated manually` | Operator review note. |
| `sort=` | No | Report grouping used for row numbering. | `finding` | Report grouping used for row numbering. |
| `status=` | No | Finding review status filter. | `open` | Finding review status filter. |

- Consumes: finding lifecycle topics.
- Visible output: prints review action results or errors.
- Emits: `finding.reviewed`.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysistechnology_indicators"></a>

### `analysis.technology_indicators`

Promotes passive technology and version evidence into finding candidates.


Use this after service probing, banner capture, HTTP probing, or web fingerprinting when
you want suspected vulnerable-version indicators to enter the normal finding review
workflow. It reads existing facts only and does not perform exploit probes,
authentication attempts, or additional network discovery.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.technology_indicators` |
| Commandlets | `technology_indicators`, `tech_review` |
| Last updated | `2026-06-04` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/technology_indicators` |

#### Commandlet: `technology_indicators`

Example usage: `http_probe https://example.test/ | webfin | technology_indicators`

Use `technology_indicators` to promote selected passive version and fingerprint signals
into normalized candidate findings. Current starter rules cover Apache httpd 2.4.49
and 2.4.50, nginx 1.3.9-1.4.0, Microsoft IIS 6.0, and OpenSSL 1.0.1-1.0.1f
plus exact vsftpd 2.3.4 and UnrealIRCd 3.2.8.1 backdoor/trojaned-distribution
indicators from server headers, banners, service evidence, or web fingerprints. The
output is intentionally a candidate with `confidence_basis` set to
`version_indicator` or `fingerprint_indicator`, not a confirmed vulnerability.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress technology indicator alerts. | `--silent` | Binary flag; suppress technology indicator alerts. |

- Consumes: `service.detected`, `tcp.banner`, `http.endpoint`,
  `web.fingerprint`.
- Visible output: prints finding alerts for promoted technology indicators
  unless `--silent` is set.
- Emits: `finding.candidate`.
- Safety boundary: passive only; no exploit probes, credential checks,
  brute force, or added scan breadth.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

#### Commandlet: `tech_review`

Example usage: `http_probe https://example.test/ | webfin | tech_review | report`

Use `tech_review` when you want the short operator path. It performs the same passive
indicator promotion as `technology_indicators`, then immediately deduplicates those
fresh candidates so `report` can show one review-ready finding group in the same chain.
It does not read unrelated historical findings.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `--silent` | No | Binary flag; suppress technology review alerts. | `--silent` | Binary flag; suppress technology review alerts. |

- Consumes: `service.detected`, `tcp.banner`, `http.endpoint`,
  `web.fingerprint`.
- Visible output: prints technology indicator alerts, dedupe decision alerts,
  and a compact `tech_review` summary unless `--silent` is set.
- Emits: `finding.candidate`, `finding.new`, `finding.duplicate`,
  `finding.updated`, `finding.merge_candidate`.
- Safety boundary: passive only; no exploit probes, credential checks,
  brute force, added scan breadth, or automatic confirmation.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysisyara_scan"></a>

### `analysis.yara_scan`

Scans files with YARA rules.


Use this to scan specific files with YARA rules and store any matches as evidence. It is
file-oriented and depends on local rules, so it fits malware, webshell, and suspicious
artifact review workflows.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.yara_scan` |
| Commandlets | `yara_scan` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/yara_scan.py bywaf/plugins/analysis/yara_scan.plugin.toml` |

#### Commandlet: `yara_scan`

Example usage: `yara_scan rule=webshells.yar shell.php`

Use `yara_scan` when you have a rule file and one or more files to inspect. Matches are
stored as `yara.match` events, while rule or scan failures are surfaced as tool errors.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<file>` | Yes | File path to scan. | `shell.php` | File path to scan. |
| `rule=` | Yes | YARA rule file. | `webshells.yar` | YARA rule file. |

- Visible output: usually quiet on success; matches are available through result
  views and failures surface as command errors or tool-error events.
- Emits: `yara.match`, `tool.error`.
- External dependency: `yara-python`.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

## Runtime

### Runtime Plugin TOC

- [runtime.artifact](#runtimeartifact)
- [runtime.audit](#runtimeaudit)
- [runtime.bundle](#runtimebundle)
- [runtime.control](#runtimecontrol)
- [runtime.inventory](#runtimeinventory)
- [runtime.job](#runtimejob)
- [runtime.key](#runtimekey)
- [runtime.name](#runtimename)
- [runtime.note](#runtimenote)
- [runtime.pipeline](#runtimepipeline)
- [runtime.results](#runtimeresults)
- [runtime.schemas](#runtimeschemas)
- [runtime.step](#runtimestep)
- [runtime.watchdog](#runtimewatchdog)

<a id="runtimeartifact"></a>

### `runtime.artifact`

Manages evidence artifacts in the paired artifact database.


Use this to manage evidence stored in Bywaf's artifact database rather than loose files.
Artifacts keep provenance, scope, names, notes, and verification metadata together with
the bytes they describe.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.artifact` |
| Commandlets | `artifact`, `search` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/artifact` |

#### Commandlet: `artifact`

Example usage: `artifact list step=12`

Use `artifact` for the full artifact lifecycle: import, attach, inspect, export,
replace, remove, search, and verify. Prefer it when evidence should remain tied to Bywaf
provenance instead of living as an unmanaged local file.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | `import`, `attach`, `cat`, `show`, `list`, `export`, `replace`, `remove`, `search`, or `verify`. | `list` | `import`, `attach`, `cat`, `show`, `list`, `export`, `replace`, `remove`, `search`, or `verify`. |
| `artifact=` | No | Artifact id selector. | `1` | Artifact id selector. |
| `serial=` | No | Runtime serial selector. | `run-abc123` | Runtime serial selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | No | Job selector. | `7` | Job selector. |
| `topic=` | No | Artifact topic selector. | `artifact.attached` | Artifact topic selector. |
| `file=` | No | File path for import, attach, replace, or export. | `snapshot.html` | File path for import, attach, replace, or export. |
| `dir=` | No | Directory path for export. | `artifacts/` | Directory path for export. |
| `name=` | No | Human-friendly artifact name. | `Landing page` | Human-friendly artifact name. |
| `note=` | No | Artifact note. | `login screenshot` | Artifact note. |
| `limit=` | No | Byte limit for `cat`. | `4096` | Byte limit for `cat`. |
| `encoding=` | No | Encoding for `cat`. | `utf-8` | Encoding for `cat`. |
| `--page` | No | Binary flag; page list or cat output. | `--page` | Binary flag; page list or cat output. |

#### Commandlet: `search`

Example usage: `search filename=evidence.txt`

Use `search` when you need to find artifacts by name, filename, note, content, scope, or
time window. Regular-expression mode is available for precise investigations, while
normal search is better for quick lookups.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `name=` | No | Search artifact names. | `login` | Search artifact names. |
| `filename=` | No | Search artifact filenames. | `screenshot` | Search artifact filenames. |
| `note=` | No | Search artifact notes. | `cookie` | Search artifact notes. |
| `content=` | No | Search artifact content. | `password` | Search artifact content. |
| `serial=` | No | Runtime serial selector. | `run-abc123` | Runtime serial selector. |
| `artifact=` | No | Artifact id selector. | `1` | Artifact id selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | No | Job selector. | `7` | Job selector. |
| `since=` | No | Start time or event selector. | `20260601` | Start time or event selector. |
| `until=` | No | End time. | `20260603` | End time. |
| `--regexp` | No | Binary flag; treat search values as regular expressions. | `--regexp` | Binary flag; treat search values as regular expressions. |

- Visible output: `list`, `show`, `cat`, `search`, and `verify` print or page
  artifact details; write actions print action results.
- Emits: artifact lifecycle events.
- Intended use: retain and inspect evidence with provenance.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimebundle"></a>

### `runtime.bundle`

Builds evidence/report bundles for handoff.


Use this to assemble evidence, audit records, and reports into a handoff bundle. Bundle
actions are useful near the end of an assessment when you need a scoped export with
optional sealing and signing.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.bundle` |
| Commandlets | `bundle` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/bundle bywaf/plugins/runtime/bundle/bywaf.plugin.toml` |

#### Commandlet: `bundle`

Example usage: `bundle add name=client-a evidence commandlet=nikto,webfin`

Use `bundle` to collect selected evidence, audit entries, and reports into a named
handoff unit. Sealing and signing actions help preserve integrity once the bundle is
ready to export.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | `create`, `add`, `list`, `show`, `seal`, `verify`, or `export`. | `add` | `create`, `add`, `list`, `show`, `seal`, `verify`, or `export`. |
| `name=` | Usually | Bundle name. | `client-a` | Bundle name. |
| `<content-kind>` | For `add` | `audit`, `evidence`, or `reports`. | `evidence` | `audit`, `evidence`, or `reports`. |
| `topic=` | No | Topic selector for bundle content. | `finding.new` | Topic selector for bundle content. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | No | Job selector. | `7` | Job selector. |
| `serial=` | No | Runtime serial selector. | `run-abc123` | Runtime serial selector. |
| `since=` | No | Start time or selector. | `20260601` | Start time or selector. |
| `until=` | No | End time or selector. | `20260603` | End time or selector. |
| `commandlet=` | No | Commandlet selector. | `nikto,webfin` | Commandlet selector. |
| `file=` | For `export` | Bundle export path. | `client-a.bundle.json` | Bundle export path. |
| `key=` | With `--sign` | Signing key name. | `firm-evidence` | Signing key name. |
| `--sign` | No | Binary flag; sign a sealed bundle. | `--sign` | Binary flag; sign a sealed bundle. |

- Visible output: prints bundle creation, add, seal, verify, show, list, and
  export summaries.
- Emits: `bundle.created`, `bundle.item.added`, `bundle.sealed`,
  `bundle.exported`.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimeaudit"></a>

### `runtime.audit`

Inspects, reports, or exports audit records.


Use this to inspect, summarize, or export the event trail behind a run. Audit output is
most useful when you need to explain what happened, preserve provenance, review
policy decisions, or produce a machine-readable activity record.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.audit` |
| Commandlets | `audit` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/audit` |

#### Commandlet: `audit`

Example usage: `audit list policy decision=warn`

Use `audit` to view or export the event trail for a scope. Exported audit files are
useful for handoff, troubleshooting, and proving how a finding or artifact was
produced. The `audit list policy` view answers operator questions about scope
enforcement: which commandlet tried to act on a target, what targets policy kept
or removed, whether the decision was allowed or warned/blocked, which warning or
repair explains the decision, and which step or job created the evidence. The
`audit list topics` view summarizes topic-contract policy events such as
undeclared-topic attempts and declared topics that had no registered schema at
publish time. These list views report existing audit events; they do not run
scanners or duplicate enforcement.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | Audit action such as `show`, `list`, or `export`. | `list` | Audit action such as `show`, `list`, or `export`. |
| `<list-target>` | For `list` | `capabilities`, `policy`, or `topics`. | `policy` | Selects an audit inventory/report view. |
| `file=` | For export | Export file path. | `audit.jsonl` | Export file path. |
| `topic=` | No | Topic selector. | `finding.new` | Topic selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | No | Job id or serial selector. | `7` | Job id or serial selector. |
| `serial=` | No | Runtime serial selector. | `run-abc123` | Runtime serial selector. |
| `since=` | No | Compact time or scoped bound such as `step:<id>`. | `20260601` | Lower audit window bound. |
| `until=` | No | Compact time or scoped bound such as `job:<id>`. | `20260602` | Upper audit window bound. |
| `plugin=` | No | Commandlet name for `list` views. | `hostscanner` | Selects capability or policy report rows for one commandlet. |
| `decision=` | No | Policy or topic-contract decision for `list policy` / `list topics`. | `warn` | Selects policy decisions by outcome. |
| `reason=` | No | Topic-contract reason for `list topics`. | `unregistered` | Selects topic-contract rows by reason. |
| `target=` | No | Target text for `list policy`. | `198.51.100.10` | Selects policy decisions whose before/after target list contains the text. |
| `format=` | No | Export format or `auto`. | `auto` | Export format or `auto`. |
| `limit=` | No | Maximum events to show or export. | `1000` | Maximum events to show or export. |
| `--encrypt` | No | Binary flag; encrypt supported exports. | `--encrypt` | Binary flag; encrypt supported exports. |

- Visible output: prints selected audit records, inventory tables, policy decision
  tables, or export summaries; encrypted exports may prompt for a passphrase.
- Emits: export artifacts when applicable.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimeinventory"></a>

### `runtime.inventory`

Provides compact domain-specific inventory views over stored facts.


Use these views to inspect stored facts by domain rather than by raw event topic. They
are read-side tools for answering questions like what hosts, web endpoints,
certificates, banners, paths, or screenshots are currently known.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.inventory` |
| Commandlets | `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`, `banners`, `paths`, `screenshots` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/inventory` |

#### Commandlets: `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`, `banners`, `paths`, `screenshots`

Example usage: `web pipeline=1 --page`

Use these inventory commandlets to inspect stored facts in domain-specific tables. Each
command name selects the view, and shared selectors such as `pipeline=`, `job=`,
`step=`, `--last`, and `--new` control the scope.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `job=` | No | Job selector. | `7` | Job selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `all=` | No | Include all rows. | `true` | Include all rows. |
| `<selector>` | No | View-specific `key=value` selector. | `host=192.0.2.10` | View-specific `key=value` selector. |
| `--last` | No | Binary flag; show latest relevant scope. | `--last` | Binary flag; show latest relevant scope. |
| `--new` | No | Binary flag; show newly observed rows. | `--new` | Binary flag; show newly observed rows. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |

- Consumes: domain-specific facts for each view.
- Visible output: prints or pages compact domain inventory tables.
- Emits: no event records; console or paged output only.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimejob"></a>

### `runtime.job`

Inspects and controls background jobs.


Use this to inspect and control background jobs. It is the job-level operational view
for long-running commandlets, including lists, detail views, and cooperative or hard
stop actions where supported.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.job` |
| Commandlets | `job` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/job` |

#### Commandlet: `job`

Example usage: `job --all`

Use `job` to list, inspect, or control background work at job granularity. It is useful
for checking progress, finding stuck work, and issuing cooperative or hard control
actions when appropriate.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<id>` | No | Job id or serial for show/control. | `7` | Job id or serial for show/control. |
| `<action>` | No | `cancel`, `end`, or `kill`. | `cancel` | `cancel`, `end`, or `kill`. |
| `<selector>` | No | Runtime list selector. | `state=running` | Runtime list selector. |
| `since=` | No | Event cursor or runtime selector. | `120` | Event cursor or runtime selector. |
| `sort=` | No | Sort key. | `started` | Sort key. |
| `--all` | No | Binary flag; include inactive rows. | `--all` | Binary flag; include inactive rows. |
| `--new` | No | Binary flag; highlight new rows. | `--new` | Binary flag; highlight new rows. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` | Binary flag; request cooperative control. |
| `--hard` | No | Binary flag; request hard control. | `--hard` | Binary flag; request hard control. |

- Visible output: prints or pages job lists/details and control-action results.
- Emits: console or paged output and framework control effects.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimepipeline"></a>

### `runtime.pipeline`

Inspects and controls pipelines.


Use this to inspect or control multi-step pipelines and attach additional commandlets to
existing pipeline context. It is the right view when scope and data flow matter more
than a single background process.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.pipeline` |
| Commandlets | `pipeline` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/pipeline` |

#### Commandlet: `pipeline`

Example usage: `pipeline attach 1 portscanner step=1`

Use `pipeline` to inspect pipeline state, attach new commandlets to an existing
pipeline, or control the pipeline as a unit. The attach form keeps downstream work tied
to the same provenance and scope.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<id>` | No | Pipeline id or serial for show/control. | `1` | Pipeline id or serial for show/control. |
| `<action>` | No | `attach`, `cancel`, `end`, or `kill`. | `attach` | `attach`, `cancel`, `end`, or `kill`. |
| `<commandlet-tail>` | For `attach` | Commandlet and arguments to attach. | `portscanner step=1` | Commandlet and arguments to attach. |
| `<selector>` | No | Runtime list selector. | `state=running` | Runtime list selector. |
| `since=` | No | Event cursor or runtime selector. | `30` | Event cursor or runtime selector. |
| `sort=` | No | Sort key. | `started` | Sort key. |
| `--all` | No | Binary flag; include inactive rows. | `--all` | Binary flag; include inactive rows. |
| `--new` | No | Binary flag; highlight new rows. | `--new` | Binary flag; highlight new rows. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` | Binary flag; request cooperative control. |
| `--hard` | No | Binary flag; request hard control. | `--hard` | Binary flag; request hard control. |

- Visible output: prints or pages pipeline lists/details and control-action
  results.
- Emits: console or paged output and framework control effects.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimestep"></a>

### `runtime.step`

Inspects pipeline steps.


Use this to inspect individual pipeline steps and their status. It is helpful when a
pipeline is large and you need to isolate the step that produced a fact, artifact,
error, or runtime state.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.step` |
| Commandlets | `step` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/step/` |

#### Commandlet: `step`

Example usage: `step --new`

Use `step` to review individual pipeline steps and isolate where specific facts,
artifacts, or errors came from. `--new` helps focus on activity since the last viewed
cursor.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<id>` | No | Step id or serial for detail view. | `12` | Step id or serial for detail view. |
| `<selector>` | No | Runtime list selector. | `host=192.0.2.10` | Runtime list selector. |
| `since=` | No | Event cursor or runtime selector. | `40` | Event cursor or runtime selector. |
| `sort=` | No | Sort key. | `started` | Sort key. |
| `--all` | No | Binary flag; include inactive rows. | `--all` | Binary flag; include inactive rows. |
| `--new` | No | Binary flag; highlight new rows. | `--new` | Binary flag; highlight new rows. |

- Visible output: prints step lists or step detail output.
- Emits: no event records; console output only.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimeresults"></a>

### `runtime.results`

Shows what the latest or selected scan found.


Use this for a quick operator summary of what a selected scan, job, or pipeline found.
It reads stored events and renders current results without producing new evidence.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.results` |
| Commandlets | `results`, `result` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/results` |

#### Commandlets: `results`, `result`

Example usage: `results job=latest`

Use `results` or `result` for a quick rendered summary of selected scan output. Follow
mode is useful while a job is still producing results; paged mode is better for longer
completed runs.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `job=` | No | Job selector or `latest`. | `latest` | Job selector or `latest`. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `all=` | No | Include all result topics. | `true` | Include all result topics. |
| `sort=` | No | Sort key for rendered results. | `port` | Sort key for rendered results. |
| `interval=` | No | Follow polling interval seconds. | `1` | Follow polling interval seconds. |
| `once=` | No | Stop follow after one render. | `true` | Stop follow after one render. |
| `--follow` | No | Binary flag; follow result updates. | `--follow` | Binary flag; follow result updates. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |

- Visible output: prints or pages rendered scan result summaries.
- Emits: no event records; console or paged output only.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimecontrol"></a>

### `runtime.control`

Requests or applies runtime control actions.


Use this for direct control commands over running or paused work. It is intentionally
explicit about targets so operators can pause, resume, cancel, stop, end, kill, or
signal the intended job, pipeline, or step.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.control` |
| Commandlets | `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/control` |

#### Commandlets: `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop`

Example usage: `pause job=7`

Use these control commandlets when work needs to pause, resume, stop, cancel, end, kill,
or receive a signal. Always provide an explicit target selector so the control action
lands on the intended runtime object.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<target>` | Yes | `job=`, `pipeline=`, `step=`, or `serial=` selector. | `job=7` | `job=`, `pipeline=`, `step=`, or `serial=` selector. |
| `<action>` | For `signal` | Signal action. | `verbosity` | Signal action. |
| `<key=value>` | No | Optional signal payload. | `level=quiet` | Optional signal payload. |
| `--soft` | No | Binary flag; request cooperative control. | `--soft` | Binary flag; request cooperative control. |
| `--hard` | No | Binary flag; request hard control where supported. | `--hard` | Binary flag; request hard control where supported. |
| `--listonly` | No | Binary flag; list resumable targets for `resume`. | `--listonly` | Binary flag; list resumable targets for `resume`. |

- Visible output: prints control request/action results or errors.
- Emits: runtime control lifecycle events.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimenote"></a>

### `runtime.note`

Shows or saves notes attached to jobs, pipelines, and pipeline steps.


Use this to attach operator context to runtime objects without changing scan evidence.
Notes are useful for manual validation, triage comments, handoff context, and explaining
why a later decision was made.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.note` |
| Commandlets | `note` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/note` |

#### Commandlet: `note`

Example usage: `note add step=12 text=validated manually`

Use `note` to show or add operator notes on a job, pipeline, or step. `text=` consumes
the rest of the line, which makes it suitable for natural review comments without extra
quoting.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `add` | No | Action token to create a note instead of showing notes. | `add` | Action token to create a note instead of showing notes. |
| `step=` | One target required | Step selector. | `12` | Step selector. |
| `pipeline=` | One target required | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | One target required | Job selector. | `7` | Job selector. |
| `text=` | For `note add` | Note text; consumes the rest of the line. | `validated manually` | Note text; consumes the rest of the line. |
| `file=` | No | Input file for `add`, or output file when showing notes. | `notes.txt` | Input file for `add`, or output file when showing notes. |

- Visible output: shows selected notes, saves notes to a file, or prints add
  results.
- Emits: note lifecycle events.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimename"></a>

### `runtime.name`

Shows or assigns human-readable names to jobs, pipelines, and pipeline steps.


Use this to give jobs, pipelines, and steps human-readable labels. Names improve
navigation and report scoping when numeric identifiers alone are too hard to remember.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.name` |
| Commandlets | `name` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/name` |

#### Commandlet: `name`

Example usage: `name pipeline=1 client subnet scan`

Use `name` to show or assign a readable label to runtime objects. Natural trailing text
and `text=` both support names that consume the rest of the command line.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `step=` | One target required | Step selector. | `12` | Step selector. |
| `pipeline=` | One target required | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | One target required | Job selector. | `7` | Job selector. |
| `text=` | No | Explicit name text; consumes the rest of the line. | `client subnet scan` | Explicit name text; consumes the rest of the line. |
| `<name text>` | No | Natural trailing name text. | `client subnet scan` | Natural trailing name text. |

- Visible output: shows the current name or prints assignment results.
- Emits: `runtime.name.assigned`.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimekey"></a>

### `runtime.key`

Manages signing keys for plugin and catalog trust workflows.


Use this to manage keys used by plugin/catalog trust and signed bundle workflows. It is
operational key management, so import/export and passphrase prompts should be handled
carefully.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.key` |
| Commandlets | `key` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/key` |

#### Commandlet: `key`

Example usage: `key generate name=firm-evidence`

Use `key` to list, generate, import, export, remove, or test trust keys. Some actions
may prompt for passphrases, and private key material should be handled as sensitive
operational data.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | `list`, `show`, `generate`, `import`, `export`, `remove`, or `test`. | `generate` | `list`, `show`, `generate`, `import`, `export`, `remove`, or `test`. |
| `<scope-token>` | For import/export | `public` or `private`. | `public` | `public` or `private`. |
| `name=` | Usually | Key name. | `firm-evidence` | Key name. |
| `file=` | For import/export | Key file path. | `firm-evidence.pub` | Key file path. |
| `scope=` | No | Key scope. | `user` | Key scope. |

- Visible output: prints key lists, key metadata, import/export/generation
  results, and test results; some actions prompt for passphrases.
- Emits: `key.generated`, `key.imported`, `key.removed`, `key.tested`.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimeschemas"></a>

### `runtime.schemas`

Inspects the active event schema catalog.


Use this when you need to understand the active event topics and fields that plugins and
framework components produce. It is especially useful for plugin authors,
troubleshooting, and confirming what downstream tools can consume.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.schemas` |
| Commandlets | `schemas` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/schemas/` |

#### Commandlet: `schemas`

Example usage: `schemas owner=plugin`

Use `schemas` to inspect event topics and fields by owner, topic prefix, detail level,
or usage. It is the quickest way to understand what facts a plugin can emit or consume.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `owner=` | No | `framework`, `plugin`, or `all`. | `plugin` | `framework`, `plugin`, or `all`. |
| `topic=` | No | Topic prefix. | `web.` | Topic prefix. |
| `detail=` | No | Include field-level detail: `true` or `false`. | `true` | Include field-level detail: `true` or `false`. |
| `sort=` | No | `topic`, `owner`, `used`, or prefixed with `-`. | `-used` | `topic`, `owner`, `used`, or prefixed with `-`. |
| `--page` | No | Binary flag; page output. | `--page` | Binary flag; page output. |

- Visible output: prints or pages schema tables and optional field details.
- Emits: no event records; console or paged output only.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimewatchdog"></a>

### `runtime.watchdog`

Monitors runtime health, stalls, and error rates.


Use this to monitor runtime health, long-running jobs, stalls, and repeated errors. In
session-service mode it acts as a background observer that emits watchdog events for
later review.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.watchdog` |
| Commandlets | `watchdog` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/watchdog` |

#### Commandlet: `watchdog`

Example usage: `watchdog --session-service`

Use `watchdog` once for an immediate health check or as a session service for continuous
monitoring. It emits timeout, stall, and error-rate events that help diagnose
long-running sessions.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `interval=` | No | Seconds between service checks. | `5` | Seconds between service checks. |
| `timeout=` | No | Seconds a job may run before warning. | `300` | Seconds a job may run before warning. |
| `stall-threshold=` | No | Seconds without job events before warning. | `120` | Seconds without job events before warning. |
| `error-threshold=` | No | Number of error events before warning. | `10` | Number of error events before warning. |
| `--once` | No | Binary flag; run one check. | `--once` | Binary flag; run one check. |
| `--session-service` | No | Binary flag; run as session service. | `--session-service` | Binary flag; run as session service. |
| `--silent` | No | Binary flag; suppress console alerts. | `--silent` | Binary flag; suppress console alerts. |

- Visible output: prints watchdog alerts unless `--silent` is set; session
  service mode primarily reports through events/alerts.
- Emits: `watchdog.timeout`, `watchdog.stalled`, `watchdog.error_rate`.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

## Storage

### Storage Plugin TOC

- [storage.db](#storagedb)

<a id="storagedb"></a>

### `storage.db`

Manages the active event database and paired artifact database.


Use this to inspect, switch, maintain, encrypt, decrypt, export, or rekey the active
event database and paired artifact database. It is the operator entry point for storage
lifecycle work, not a scanner.

Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Storage |
| Plugin | `storage.db` |
| Commandlets | `db` |
| Last updated | `2026-06-03` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/storage/db.py bywaf/plugins/storage/db.plugin.toml` |

#### Commandlet: `db`

Example usage: `db status`

Use `db` for database status, path, maintenance, load/export, encryption, decryption,
and rekey operations. Encryption actions protect both the event database and paired
artifact database when enabled.

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | `status`, `stats`, `path`, `checkpoint`, `vacuum`, `new`, `load`, `export`, `encrypt`, `decrypt`, or `rekey`. | `status` | `status`, `stats`, `path`, `checkpoint`, `vacuum`, `new`, `load`, `export`, `encrypt`, `decrypt`, or `rekey`. |
| `file=` | For `new`, `load`, `export` | Database path. | `client.sqlite3` | Database path. |
| `--encrypt` | No | Binary flag; encrypt a new or exported database. | `--encrypt` | Binary flag; encrypt a new or exported database. |
| `--force` | No | Binary flag; bypass interactive confirmation where supported. | `--force` | Binary flag; bypass interactive confirmation where supported. |

- Visible output: prints database status, stats, paths, maintenance summaries,
  load/export results, and passphrase prompts for encryption actions.
- Security note: SQLCipher encryption protects the main event DB and paired
  artifact DB at rest when enabled.

[Back to Storage plugin TOC](#storage-plugin-toc) | [Back to document Storage TOC entry](#toc-storage)
