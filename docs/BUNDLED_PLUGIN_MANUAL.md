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
<details class="plugin-toc-family">
<summary id="toc-analysis"><span class="toc-count">5</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Analysis</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfinding">analysis.finding</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfinding_dedupe">analysis.finding_dedupe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisfinding_report">analysis.finding_report</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisreport">analysis.report</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#analysisyara_scan">analysis.yara_scan</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-discovery"><span class="toc-count">1</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">Discovery</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#discoveryhostscanner">discovery.hostscanner</a></span></div>
</details>
<details class="plugin-toc-family">
<summary id="toc-http"><span class="toc-count">10</span><span class="toc-arrow" aria-hidden="true">▸</span><span class="toc-name">HTTP</span></summary>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpeyewitness">http.eyewitness</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httphttp_headers">http.http_headers</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httphttp_paths">http.http_paths</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httphttp_probe">http.http_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpnikto">http.nikto</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">2</span><span class="toc-name"><a href="#httprepo_exposure">http.repo_exposure</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpscreenshotter">http.screenshotter</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httptls_probe">http.tls_probe</a></span></div>
<div class="toc-entry"><span class="toc-count toc-child-count">1</span><span class="toc-name"><a href="#httpwaf_detect">http.waf_detect</a></span></div>
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
| HTTP | `http.http_headers` | `http_headers` | Collect HTTP headers and header findings. | `http_headers ssl=true example.com` | [http.http_headers](#httphttp_headers) |
| HTTP | `http.http_probe` | `http_probe` | Publish reusable HTTP endpoint facts. | `http_probe https://example.com/` | [http.http_probe](#httphttp_probe) |
| HTTP | `http.http_paths` | `http_paths` | Check explicit or common web paths. | `http_paths paths=/.git/config,/.env https://example.com/` | [http.http_paths](#httphttp_paths) |
| HTTP | `http.repo_exposure` | `repo_exposure`, `git_expose_check` | Check for exposed repository metadata. | `http_probe https://example.com/ \| repo_exposure` | [http.repo_exposure](#httprepo_exposure) |
| HTTP | `http.webfin` | `webfin` | Fingerprint web technologies. | `http_probe https://example.com/ \| webfin` | [http.webfin](#httpwebfin) |
| HTTP | `http.tls_probe` | `tls_probe` | Collect TLS certificate and hygiene facts. | `tls_probe https://example.com/` | [http.tls_probe](#httptls_probe) |
| HTTP | `http.waf_detect` | `waf_detect` | Detect likely WAF/CDN signals. | `waf_detect https://example.com/` | [http.waf_detect](#httpwaf_detect) |
| HTTP | `http.nikto` | `nikto` | Wrap Nikto and normalize findings. | `http_probe https://example.com/ \| nikto` | [http.nikto](#httpnikto) |
| HTTP | `http.eyewitness` | `eyewitness` | Capture web screenshots through EyeWitness. | `http_probe https://example.com/ \| eyewitness` | [http.eyewitness](#httpeyewitness) |
| HTTP | `http.screenshotter` | `screenshotter` | Friendly EyeWitness-backed screenshot commandlet. | `http_probe https://example.com/ \| screenshotter` | [http.screenshotter](#httpscreenshotter) |
| Wireless | `wireless.wifi_scan` | `wifi_scan` | Wrap Kismet-style wireless scans. | `wifi_scan interface=wlan0mon duration=60` | [wireless.wifi_scan](#wirelesswifi_scan) |
| Analysis | `analysis.finding_dedupe` | `finding_dedupe` | Normalize and deduplicate findings. | `nikto https://example.com/ \| finding_dedupe` | [analysis.finding_dedupe](#analysisfinding_dedupe) |
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

## OS

### OS Plugin TOC

- [os.cat](#oscat)
- [os.less](#osless)
- [os.ls](#osls)


<a id="osls"></a>

### `os.ls`

Lists local files from inside the Bywaf interpreter.


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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Recon |
| Plugin | `recon.dns_lookup` |
| Commandlets | `dns_lookup` |
| Last updated | `2026-06-01` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/recon/dns_lookup.py bywaf/plugins/recon/dns_lookup.plugin.toml` |

#### Commandlet: `dns_lookup`

Example usage: `dns_lookup record-type=MX example.com`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Recon |
| Plugin | `recon.dns_enum` |
| Commandlets | `dns_enum` |
| Last updated | `2026-06-01` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/recon/dns_enum.py bywaf/plugins/recon/dns_enum.plugin.toml` |

#### Commandlet: `dns_enum`

Example usage: `dns_enum domain=example.com words=www,api`

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
- [http.http_headers](#httphttp_headers)
- [http.http_paths](#httphttp_paths)
- [http.http_probe](#httphttp_probe)
- [http.nikto](#httpnikto)
- [http.repo_exposure](#httprepo_exposure)
- [http.screenshotter](#httpscreenshotter)
- [http.tls_probe](#httptls_probe)
- [http.waf_detect](#httpwaf_detect)
- [http.webfin](#httpwebfin)

<a id="httphttp_headers"></a>

### `http.http_headers`

Collects HTTP response headers and promotes missing high-value security headers.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.http_headers` |
| Commandlets | `http_headers` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/http_headers bywaf/plugins/http/http_headers/bywaf.plugin.toml` |

#### Commandlet: `http_headers`

Example usage: `http_headers ssl=true example.com`

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

<a id="httphttp_probe"></a>

### `http.http_probe`

Probes HTTP endpoints and publishes reusable endpoint facts.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.http_probe` |
| Commandlets | `http_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/http_probe.py bywaf/plugins/http/http_probe.plugin.toml` |

#### Commandlet: `http_probe`

Example usage: `http_probe https://example.com/`

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

<a id="httphttp_paths"></a>

### `http.http_paths`

Checks common or explicitly supplied HTTP paths.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.http_paths` |
| Commandlets | `http_paths` |
| Last updated | `2026-06-03` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/http_paths.py bywaf/plugins/http/http_path_findings.py bywaf/plugins/http/http_paths.plugin.toml` |

#### Commandlet: `http_paths`

Example usage: `http_paths paths=/.git/config,/.env https://example.com/`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.webfin` |
| Commandlets | `webfin` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/webfin.py bywaf/plugins/http/webfin.plugin.toml` |

#### Commandlet: `webfin`

Example usage: `http_probe https://example.com/ | webfin`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.tls_probe` |
| Commandlets | `tls_probe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/tls_probe.py bywaf/plugins/http/tls_probe.plugin.toml` |

#### Commandlet: `tls_probe`

Example usage: `tls_probe https://example.com/`

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

<a id="httpnikto"></a>

### `http.nikto`

Runs Nikto through the framework process API and normalizes selected output.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | HTTP |
| Plugin | `http.nikto` |
| Commandlets | `nikto` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/http/nikto.py bywaf/plugins/http/nikto_findings.py bywaf/plugins/http/nikto.plugin.toml` |

#### Commandlet: `nikto`

Example usage: `http_probe https://example.com/ | nikto`

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
- [analysis.finding_dedupe](#analysisfinding_dedupe)
- [analysis.finding_report](#analysisfinding_report)
- [analysis.report](#analysisreport)
- [analysis.yara_scan](#analysisyara_scan)

<a id="analysisfinding_dedupe"></a>

### `analysis.finding_dedupe`

Normalizes and deduplicates raw finding streams.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.finding_dedupe` |
| Commandlets | `finding_dedupe` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/finding_dedupe.py bywaf/plugins/analysis/finding_dedupe.plugin.toml` |

#### Commandlet: `finding_dedupe`

Example usage: `nikto https://example.com/ | finding_dedupe`

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

<a id="analysisfinding_report"></a>

### `analysis.finding_report`

Renders finding tables and exports report artifacts.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.finding_report` |
| Commandlets | `finding_report` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/finding_report.py bywaf/plugins/analysis/finding_report.plugin.toml` |

#### Commandlet: `finding_report`

Example usage: `finding_report export=findings.md`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Analysis |
| Plugin | `analysis.report` |
| Commandlets | `report` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/analysis/report bywaf/plugins/analysis/report.plugin.toml` |

#### Commandlet: `report`

Example usage: `report accept 1-3 pipeline=1`

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
| `page=` | No | Page rendered report output: `true` or `false`. | `false` | Page rendered report output: `true` or `false`. |
| `sort=` | No | Group report rows by `finding` or `host`. | `host` | Group report rows by `finding` or `host`. |
| `status=` | No | Review status filter. | `open` | Review status filter. |
| `--last` | No | Binary flag; show latest scan/reportable pipeline. | `--last` | Binary flag; show latest scan/reportable pipeline. |
| `--new` | No | Binary flag; show newly introduced facts. | `--new` | Binary flag; show newly introduced facts. |
| `--accepted-first` | No | Binary flag; show accepted findings before other states. | `--accepted-first` | Binary flag; show accepted findings before other states. |
| `--candidates-first` | No | Binary flag; show candidate or potential findings first. | `--candidates-first` | Binary flag; show candidate or potential findings first. |

- Consumes: finding lifecycle topics plus report context facts.
- Visible output: renders a compact finding inbox, detailed finding views, or
  network summary tables; review actions print action results/errors.
- Emits: `report.rendered`, `report.scope.saved`, `finding.reviewed`.

[Back to Analysis plugin TOC](#analysis-plugin-toc) | [Back to document Analysis TOC entry](#toc-analysis)

<a id="analysisfinding"></a>

### `analysis.finding`

Lower-level commandlet for confirming or unconfirming finding rows.


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

<a id="analysisyara_scan"></a>

### `analysis.yara_scan`

Scans files with YARA rules.


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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.artifact` |
| Commandlets | `artifact`, `search` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/artifact bywaf/plugins/runtime/artifact.plugin.toml` |

#### Commandlet: `artifact`

Example usage: `artifact list step=12`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.bundle` |
| Commandlets | `bundle` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/bundle.py bywaf/plugins/runtime/bundle.plugin.toml` |

#### Commandlet: `bundle`

Example usage: `bundle add name=client-a evidence commandlet=nikto,webfin`

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

Inspects or exports audit records.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.audit` |
| Commandlets | `audit` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/audit bywaf/plugins/runtime/audit.plugin.toml` |

#### Commandlet: `audit`

Example usage: `audit export file=audit.jsonl`

| Argument / option | Required? | Type / accepted values | Sample value | Meaning |
| --- | --- | --- | --- | --- |
| `<action>` | Yes | Audit action such as `show`, `list`, or `export`. | `export` | Audit action such as `show`, `list`, or `export`. |
| `file=` | For export | Export file path. | `audit.jsonl` | Export file path. |
| `topic=` | No | Topic selector. | `finding.new` | Topic selector. |
| `step=` | No | Step selector. | `12` | Step selector. |
| `pipeline=` | No | Pipeline selector. | `1` | Pipeline selector. |
| `job=` | No | Job id or serial selector. | `7` | Job id or serial selector. |
| `serial=` | No | Runtime serial selector. | `run-abc123` | Runtime serial selector. |
| `format=` | No | Export format or `auto`. | `auto` | Export format or `auto`. |
| `limit=` | No | Maximum events to show or export. | `1000` | Maximum events to show or export. |
| `--encrypt` | No | Binary flag; encrypt supported exports. | `--encrypt` | Binary flag; encrypt supported exports. |

- Visible output: prints selected audit records or export summaries; encrypted
  exports may prompt for a passphrase.
- Emits: export artifacts when applicable.

[Back to Runtime plugin TOC](#runtime-plugin-toc) | [Back to document Runtime TOC entry](#toc-runtime)

<a id="runtimeinventory"></a>

### `runtime.inventory`

Provides compact domain-specific inventory views over stored facts.


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.inventory` |
| Commandlets | `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`, `banners`, `paths`, `screenshots` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/inventory.py bywaf/plugins/runtime/inventory.plugin.toml bywaf/plugins/runtime/inventory_views` |

#### Commandlets: `hosts`, `services`, `web`, `wafs`, `shares`, `routes`, `certs`, `banners`, `paths`, `screenshots`

Example usage: `web pipeline=1 --page`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.job` |
| Commandlets | `job` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/job.py bywaf/plugins/runtime/job.plugin.toml` |

#### Commandlet: `job`

Example usage: `job --all`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.pipeline` |
| Commandlets | `pipeline` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/pipeline.py bywaf/plugins/runtime/pipeline.plugin.toml` |

#### Commandlet: `pipeline`

Example usage: `pipeline attach 1 portscanner step=1`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.step` |
| Commandlets | `step` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/step.py bywaf/plugins/runtime/step.plugin.toml` |

#### Commandlet: `step`

Example usage: `step --new`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.results` |
| Commandlets | `results`, `result` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/results bywaf/plugins/runtime/results.plugin.toml` |

#### Commandlets: `results`, `result`

Example usage: `results job=latest`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.control` |
| Commandlets | `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/control bywaf/plugins/runtime/control.plugin.toml` |

#### Commandlets: `signal`, `end`, `kill`, `cancel`, `pause`, `resume`, `stop`

Example usage: `pause job=7`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.note` |
| Commandlets | `note` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/note.py bywaf/plugins/runtime/note.plugin.toml` |

#### Commandlet: `note`

Example usage: `note add step=12 text=validated manually`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.name` |
| Commandlets | `name` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/name.py bywaf/plugins/runtime/name.plugin.toml` |

#### Commandlet: `name`

Example usage: `name pipeline=1 client subnet scan`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.key` |
| Commandlets | `key` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/key.py bywaf/plugins/runtime/key.plugin.toml` |

#### Commandlet: `key`

Example usage: `key generate name=firm-evidence`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.schemas` |
| Commandlets | `schemas` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/schemas.py bywaf/plugins/runtime/schemas.plugin.toml` |

#### Commandlet: `schemas`

Example usage: `schemas owner=plugin`

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


Plugin metadata:

| Field | Value |
| --- | --- |
| Family | Runtime |
| Plugin | `runtime.watchdog` |
| Commandlets | `watchdog` |
| Last updated | `2026-06-02` from source history |
| Change info | [CHANGELOG.md](../CHANGELOG.md); inspect source history with `git log -- bywaf/plugins/runtime/watchdog.py bywaf/plugins/runtime/watchdog.plugin.toml` |

#### Commandlet: `watchdog`

Example usage: `watchdog --session-service`

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
