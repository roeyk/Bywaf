# TODO

Planning dates are release planning markers, not compatibility commitments.

## Current Release

- Bywaf 0.12.0 testing release: 2026-05-26.
- Release package metadata updated to 0.12.0 across Python, Debian, README,
  usage guide, changelog, and release artifacts.
- Release highlights captured: host filters for `event`, `jobs`, `pipelines`,
  and `steps`; event sorting; `portscanner host=` DNS resolution provenance;
  fully-qualified commandlet execution while a provider is in scope; reporting
  triage actions; database backend protocol typing; and package build metadata
  cleanup.
- Installation documentation now has a dedicated `INSTALL.md` with runtime,
  source checkout, package install, optional plugin dependency, and release
  package build dependency blocks.
- Release artifacts rebuilt for pip, Debian, and RPM. Package smoke checks
  passed for pip and RPM, and GitHub release artifacts were attached to
  `v0.12.0`.

## Target: Next Testing Release

### Item: Source Code Documentation Pass

- Add phase-oriented comments and expanded public docstrings to dense runtime
  paths, focusing on why each block exists rather than restating individual
  assignments.
- Prioritize functions with multiple responsibilities: parsing plus dispatch,
  cursoring plus audit writes, database mutation plus process control, plugin
  trust enforcement, and shell/completion adapters.
- Initial high-value inventory from an AST scan includes:
  `bywaf/triggers.py`, `bywaf/runner/core.py`, `bywaf/runner/context.py`,
  `bywaf/registry/core.py`, `bywaf/registry/manifest.py`, `bywaf/db/events.py`,
  `bywaf/db/runtime.py`, `bywaf/plugin/context.py`,
  `bywaf/plugin/services.py`, `bywaf/plugin/process.py`,
  `bywaf/command/parser.py`, `bywaf/completion/engine.py`, and bundled
  vulnerability/reporting plugins.
- Keep changes comment/docstring-only unless a function is too dense to explain
  honestly without extracting helpers; if refactoring is needed, split it into
  a separate behavioral review.

### Item: Rock-Solid MVP Plugins

- Harden the MVP plugin suite around realistic end-to-end assessment chains:
  discovery, port scanning, HTTP probing, fingerprinting, vulnerability
  probing, dedupe, reporting, artifacts, notes, and bundle export.
- Manual finding/report testing checklist:
  - Run built-in finding producers: `portscanner` for Telnet-like/open-port
    cases, `http_headers` for HTTPS targets missing HSTS or
    `X-Content-Type-Options`, and
    `http/repo_exposure/git_expose_check` against a controlled server exposing
    `/.git/config`.
  - Exercise the Telnet-like finding path with
    `network/portscanner host=<host> ports=23,2323 arguments="-Pn -sT"`,
    then inspect `event finding.candidate` and `report`.
  - Exercise repository exposure with
    `http/repo_exposure/git_expose_check target=http://<test-host>`, then
    inspect `event finding.candidate` and `report`.
  - Exercise triage with `report accept all note="confirmed in manual pass"`,
    then run `report` and `event finding.reviewed`.
  - Inspect `event finding.candidate` and confirm each finding has `class`,
    `target_scope`, `group_key`, `identifiers`, `target`, and `affected`.
  - Run `report` and `report pipeline=<id>` and verify events with the same
    `class + target_scope + CVE/CWE` collapse into one group.
  - Use `report accept`, `report defer note=...`, and `report reject` on a
    controlled set, then confirm the default report view hides reviewed
    findings and `status=all` still shows the full set with review counts.
  - Simulate the same CVE on `/`, `/admin`, and `/login` with
    `target_scope={"kind":"web_origin","value":"https://host"}` and confirm
    reporting groups them together.
  - Repeat the same route set with `target_scope.kind="web_route"` and confirm
    reporting splits them into route-specific findings.
- Add focused fixture-based tests for each MVP plugin so regressions are caught
  without requiring live third-party services for ordinary CI.
- Review commandlet output, event payloads, completion specs, manifests,
  capabilities, secret options, and error messages for consistency.
- Make the native, library-backed, process-wrapped, helper/provider, listener,
  and service-plugin examples clearly visible in documentation and tests.

### Item: Semantic Display Roles And Theme Configuration

- Add a structured display/theme configuration model under `display/...` for
  subjects such as timestamp, provider, commandlet, arguments, host,
  port, protocol, event topic, severity, finding status, job, pipeline, and
  step identifiers.
- Renderers should ask for subjects such as `host`,
  `severity.high`, or `finding.status.accepted`; they should not hard-code
  terminal colors at each call site.
- Plugins should emit structured payload fields and optional subject hints
  for non-obvious fields. They should describe what a value means, not choose
  terminal colors directly.
- Keep the initial theme format simple and terminal-safe, with names like
  `dim`, `red`, `green`, `yellow`, `cyan`, `magenta`, and `bold`, then let
  richer frontends map the same subjects into GUI/web styles.
- Let users configure either portable color/style names or explicit RGB/hex
  values per subject. Terminal renderers should gracefully degrade RGB
  values when truecolor is unavailable; GUI/web renderers can use the precise
  values directly.
- Treat unquoted `#` as the REPL/script comment marker; document quoted hex
  values such as `set display/style.host="#00ff00"` and safe alternatives such
  as `rgb:0,255,0` or `color46`.
- Let users configure visible comment styling through `display/style.comment`.
- Document the plugin contract so authors know how to expose semantically typed
  data without coupling plugin output to one frontend.

### Item: CVE Detection And Confirmation Plugins

- Research a short list of high-value, low-hanging-fruit CVE checks from
  current authoritative advisories before implementation.
- Prefer safe confirmation plugins that use version/banner/header/config
  evidence and non-destructive probes over exploit-style behavior.
- For each selected CVE, document affected products/versions, required
  authorization, probe method, false-positive limits, emitted topics, and
  artifact evidence.
- Emit normalized vulnerability events that downstream plugins can dedupe,
  report, and bundle without scraper-specific parsing.
- Keep CVE checks small and composable so they can be run after existing HTTP,
  SSH, SMB, LDAP, DNS, or fingerprinting commandlets.

### Item: Repository And Cloud Exposure Plugin Families

- Build a small family of repository-exposure plugins for HTTP-accessible
  source-control metadata and repository artifacts, starting with
  `git_expose_check` for exposed `.git/config`.
- Consider follow-up checks for exposed `.svn/`, `.hg/`, `.bzr/`, source maps,
  repository archives, backup trees, and cloud-hosted revision-control metadata
  where safe passive probes can confirm exposure.
- Build a separate cloud-exposure family for misconfigured cloud assets such as
  public object buckets, default or absent access controls, overly broad
  anonymous permissions, and exposed cloud metadata or configuration endpoints.
- Keep cloud checks authorization-first and provider-aware. Prefer
  non-destructive listing, HEAD, metadata, and policy-inspection probes over
  write tests unless explicitly enabled by the operator.
- Normalize both families into `finding.candidate` / future
  `finding.confirmed` events so report, dedupe, and artifact workflows can
  treat them consistently.

### Item: Orchestrator Commandlets For Related Check Sets

- Expose related sets of checks as normal commandlets, not a separate `scan`,
  `profile`, or `playbook` execution verb.
- Examples: `repo_exposure @urls.txt`, `cloud_exposure @assets.txt`, and
  `web_baseline example.com`.
- Let orchestrator commandlets coordinate lower-level commandlets or shared
  detection logic while preserving normal pipeline/job/step provenance.
- Improve target-file ergonomics so target-taking commandlets can treat
  `@targets.txt` as line-wise target input by default, without requiring users
  to type `@lines:targets.txt`.
- Defer named target-set storage until plain files and existing `@file`
  expansion are proven insufficient.

### Framework Request IPC

- Expand framework-owned request helpers beyond prompt, output, alerts, file
  paging, and process execution when a commandlet needs interpreter-owned
  behavior.
- Add request/response documentation for frontend authors implementing terminal,
  GUI, or web clients.
- Refine the request and outcome conventions in `DESIGN.md`.
- Add request/response helpers for any future long-running framework-owned
  operations that need asynchronous frontend handling.

### Plugin Capability Model

- Decide how strict enforcement should be for trusted local plugins versus
  third-party plugins.
- Add enforcement modes for missing capabilities after audit-only mode has been
  exercised with real plugins.
- Add policy checks for direct process execution and require `process.run` for
  mediated external tool wrappers.
- Split future deep-dive docs from `CAPABILITY_MODEL.md` if needed, such as
  `PLUGIN_TYPES.md`, `PLUGIN_SECURITY_MODEL.md`, and `PLUGIN_PACKAGING.md`.

### External Tool Wrappers

- Add more plugins that wrap established external tools and normalize their
  output into the central event database.
- Prioritize wrappers that remove manual handoffs between scan phases.

### Item: Plugin Packaging

- Define how third-party plugins are packaged, installed, discovered, trusted,
  and upgraded independently from the core Bywaf package.
- Preserve explicit plugin loading as the scaling model: Bywaf should be able
  to ship or discover large plugin catalogs without importing every plugin at
  startup, following the same practical pressure Metasploit has with thousands
  of modules.
- Decide whether Bywaf should auto-discover user-local and system-wide plugin
  config files, or keep those paths explicit until the plugin trust model is
  stricter.
- Continue refining stock plugin directory/search-path behavior for future
  system-wide plugin directories.
- Consider future provider-role binding for portable plugin families that need
  shared ancestor configuration without assuming a fixed final catalog path.
  Keep public provider variables immediate-provider-only until a manifest-backed
  role/permission model exists.
- Document recommended plugin package layouts for pip, Debian, RPM, and
  unpacked local development plugins.

### Item: MVP Plugin Suite

- Build a small, rock-solid plugin suite that demonstrates the main plugin
  integration styles: native user-facing, library-backed, external-tool
  wrapper, and helper/provider.
- Treat the existing `hostscanner` and `portscanner` commandlets as
  library-backed examples around libnmap/nmap-backed discovery and port
  scanning.
- Treat the table rendering provider as the helper/provider example: it is
  framework-native and mainly exists for other commandlets to use.
- Expand the new native `webfin` plugin into the user-facing native pentesting
  example, and keep `web_fingerprint` plus `scope_audit` as naming/design
  candidates for future native commandlets if they become separate behaviors.
- Keep the Nikto wrapper plugin as the external-tool wrapper example: it
  invokes Nikto through the framework-mediated process API, parses JSON output
  into structured finding and vulnerability events, and consumes upstream HTTP
  endpoint/fingerprint events from the Bywaf event database.
- Treat `eyewitness` and `wifi_scan` as additional external-tool wrapper
  examples covering screenshot artifacts and wireless scan logs.
- Treat `finding_dedupe` as the native finding-normalization step that prepares
  scanner output for a later reporter plugin using the framework table
  provider.
- Add at least one documented end-to-end chain showing discovery, port
  scanning, HTTP probing, screenshots, Nikto scanning, table/report output,
  notes, and artifacts.

### Item: Plugin Helper Abstraction After Real Plugin Experience

- Implement more real vulnerability-detection plugins before adding a shared
  helper abstraction for target iteration, cancellation, variable defaults,
  finding publication, or JSON-safe result conversion.
- Track repeated boilerplate across native, library-backed, and
  process-wrapped vulnerability plugins.
- If the same orchestration code appears in several production plugins, add
  small documented helper functions rather than a large abstract base class.
- Keep the current expanded skeletons as teaching references until real plugin
  implementations show which parts can be safely collapsed.

### Item: Storage Adapter Boundary And DB Agnosticism

- Keep SQLite as the production storage adapter for now. The first backend seam
  exists through `bywaf.db.backends`; continue reducing hard-coded SQL and
  SQLite-specific assumptions behind explicit storage interfaces.
- Define repository/service boundaries for events, runtime state, jobs,
  variables, artifacts, migrations, and project archive/export workflows before
  attempting a second database backend.
- Inventory assumptions that a non-SQLite backend would need to reproduce:
  local-file project semantics, durable event ordering, artifact DB pairing,
  SQLCipher encryption, transaction behavior, migrations, and archive/export
  layout.
- Add adapter-level tests that exercise the storage contract without depending
  on a specific SQL dialect. Use SQLite as the reference implementation until a
  second adapter exposes real portability pressure.
- Defer Postgres or other backend support until the storage contract is small,
  documented, and covered by tests.

### Item: Core Module Package Layout Follow-Ups

- Done: command, completion, config, finding, plugin process, secret, and DB
  schema/backend code now live in focused packages.
- Follow-up: look for remaining large runtime commandlets and repeated
  report/finding helper code that would benefit from small shared helpers.
- Preserve plugin implementation directories under `bywaf/plugins/...`; this
  item is about core framework module organization, not flattening or moving
  plugin-owned files.

### GUI/Web Frontend

- Build a local GUI or web frontend on top of `BywafSession`.
- Render events, jobs, command output, file paging, and framework requests
  without scraping REPL text.

### Job Control

- Add richer cooperative job control such as pause/resume if commandlets can
  support it cleanly.
- Define pause/resume semantics separately from cancel/kill. Current job
  control supports cooperative cancellation and signal-based termination only.
- For future target-removal or target-skip requests, prefer structured control
  signals to commandlets instead of framework mutation of plugin-owned queues.
  Soft-paused commandlets can react immediately; hard-paused OS processes must
  persist the request and check it immediately after resume.
- Improve cancellation tests so background child-process failures do not print
  noisy tracebacks during otherwise passing test runs.

### Bundle Deliverable Export

- Treat `bundle export` as a client-facing deliverable/evidence package, not a
  database export.
- Exclude SQLite databases and internal runtime state from normal client
  bundles.
- Include selected reports, artifacts, screenshots, scan outputs, delivery
  notes, and provenance summaries.
- Produce password-protected `.bywaf.zip` files when requested. Accept passwords
  through an interactive prompt or existing secret variables such as
  `password=$bundle_password`; reject plaintext literal passwords.
- Sign a manifest inside the zip rather than signing the zip container. The
  manifest should list each included file path, SHA-256 digest, size, type, and
  provenance.
- Provide recipient-friendly verification, for example
  `bundle verify file=client-a.bywaf.zip key=...`, that checks the manifest
  signature and file hashes after password entry when the bundle is encrypted.
- If internal archival with databases is needed later, make it an explicit
  separate mode such as `bundle archive`, not the default client export.

### Packaging

- Upload the 0.9.x source and wheel artifacts to TestPyPI, then PyPI, and
  verify installation from PyPI in a clean virtual environment.
- Keep pip, Debian, RPM, and plugin install-path smoke scripts aligned as
  packaging behavior changes.
- Keep user-local state in `~/.bywaf/`; do not package generated local DB,
  history, cache, or virtualenv files.

## Completed After 0.9.0

- 2026-05-18: Added persistent release builders for pip source/wheel artifacts
  under `dist/` and RPM artifacts under `dist/rpm/`.
- 2026-05-18: Added persistent Debian release artifacts under `dist/deb/` and
  a tag-driven GitHub Actions workflow that builds, smoke-tests, uploads, and
  attaches pip, Debian, and RPM artifacts to GitHub Releases.
- 2026-05-18: Built and smoke-tested pip source/wheel distributions, the
  Debian package, and RPM source/noarch packages from the packaging scaffolds.
- 2026-05-18: Verified packaged installs expose a normal `bywaf` executable,
  include `bywaf/plugins/plugins.json`, and include bundled stock commandlet
  modules.
- 2026-05-18: Added the initial Debian packaging scaffold and declared packaged
  plugin metadata.
- 2026-05-18: Added regression coverage and a reusable smoke script for
  user-local and system-wide shaped plugin roots.
- 2026-05-18: Added an installed-package smoke wrapper for validating an
  installed `bywaf` executable.
- 2026-05-13: Added audit-only plugin capability declarations and
  `plugin.capability.used` / `plugin.capability.missing` events.
- 2026-05-13: Added pipeline control plus `kill` / `cancel` selector
  commandlets for jobs and pipelines.
- 2026-05-13: Added class-based commandlet metadata decorators for plugin
  authors.
- 2026-05-14: Converted bundled commandlets to class-based metadata decorators.
- 2026-05-13: Added framework-owned paging through `context.page_file()` and
  `framework.file.page.requested`.
- 2026-05-14: Added `audit show` / `audit export` for JSON, JSONL, and SQLite
  audit handoff.
- 2026-05-14: Added framework-mediated process execution through
  `context.process.run()` and line-oriented `context.process.stream()`.
- 2026-05-17: Added framework-level `note=` parsing and `note.attached` audit
  events for commandlet steps.
- 2026-05-17: Added `note` commandlet for timestamped note review and
  `file=` export by step, pipeline, or job.
- 2026-05-17: Added append-only post-hoc notes with `note add`.
- 2026-05-17: Added framework-level at-file expansion and filename completion
  for `@`, `@@`, `@raw:`, and `@lines:`.
- 2026-05-17: Added backslash command continuation and semicolon command
  sequences.
- 2026-05-17: Added `pipelines` alias and timestamp-first history display.
- 2026-05-17: Added canonical architecture documents for terminology, runtime,
  events, capabilities, and system block/dataflow diagrams.
