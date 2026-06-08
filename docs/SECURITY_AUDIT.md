# Security Audit

This page records the current adversarial review scope for Bywaf's pre-release
runtime. It is not a guarantee that Bywaf is sandboxed. It is a map of the
surfaces that need review before releases and the controls that currently exist.
For a concise release and plugin-expansion checklist, see
[Safe Defaults Checklist](SAFE_DEFAULTS_CHECKLIST.md).

## Contents

- [Scope](#scope)
- [Current Controls](#current-controls)
- [Review Checklist](#review-checklist)
- [Known Limits](#known-limits)
- [Release Gate](#release-gate)

## Scope

Review these areas before a testing release:

- bundled plugins and their manifests;
- filesystem plugin loading, manifest signatures, and catalog trust;
- capability declarations and effective database actions;
- plugin-facing context surface and topology boundaries;
- artifact import, export, replacement, deletion, and bundle inclusion;
- secret input, secret persistence, redaction, and process/env handling;
- framework-mediated process wrappers and streamed process output;
- trigger actions, background jobs, and watchdog/service startup;
- pager/file rendering paths;
- database, artifact database, project archive, config, and history files;
- package build scripts and release metadata.

## Current Controls

- Process wrappers use argv vectors with `shell=False`; shell execution is only
  available through the explicit operator `exec` command.
- Framework process request/result events redact known in-memory secret values
  from argv, env, stdout, stderr, and streamed process output.
- The pager invokes `less` with `LESSSECURE=1` and an option terminator before
  the file path.
- Filesystem plugin packages require manifests. Trusted loading can require
  signed manifests for sidecar metadata integrity or signed catalogs for
  reviewed-tree integrity that binds `plugin.py` and `bywaf.plugin.toml`
  hashes.
- Capability auditing records declared and missing capability use; enforcement
  mode can deny undeclared mediated framework requests.
- Effective `database.actions.*` metadata lets view-only commandlet invocations
  be separated from write/review/manage invocations.
- Plugin context APIs are data-aware rather than topology-aware. Commandlets can
  read their own IDs, consume upstream events, and request a mediated pipeline
  stop, but should not receive the full pipeline plan or downstream commandlet
  list.
- Artifact storage records size and SHA-256 and `artifact verify` compares
  artifact bodies with main-DB provenance events.
- Private key files are written with owner-only permissions on normal POSIX
  filesystems.

## Review Checklist

For code changes, check:

- Does any plugin import `subprocess`, open sockets, read/write files, or call
  framework internals directly instead of using mediated context APIs?
- Are all process-wrapped tools using argv lists, bounded timeouts where
  practical, `framework.process.*` capabilities, and redacted audit events?
- Does any new context API expose workflow topology, raw stores, or mutable
  framework internals without an explicit capability and test?
- Can any user-controlled path be interpreted as an option by an external tool?
- Can an artifact export overwrite an unexpected file, follow a symlink, or hide
  provenance?
- Are secrets present in command history, runtime rows, framework request
  payloads, process result payloads, or rendered tables?
- Do manifests declare capabilities, database actions, secret options, and
  external tool traits accurately?
- Can a trigger recurse, start unbounded jobs, or run without explicit trust?
- Do package scripts build from the checked-out source and write artifacts only
  under `dist/`?
- Are `pyproject.toml`, `bywaf.__version__`, Debian changelog, RPM spec, README
  package examples, and changelog aligned?

## Known Limits

- Capability enforcement covers mediated framework APIs. A malicious in-process
  Python plugin can still attempt direct imports unless stronger plugin process
  isolation is added.
- Library-backed plugins share the Bywaf process and therefore share Python
  memory-safety and dependency-risk boundaries.
- Operator-directed filesystem commands can read or write paths the operating
  system account can access; Bywaf does not currently impose a chroot or project
  filesystem sandbox.
- Plaintext databases and plaintext artifact stores protect integrity better
  than confidentiality. Use encrypted database/artifact storage for sensitive
  assessments.

## Release Gate

Before tagging a release that changes plugins, policy, artifacts, secrets,
process wrappers, triggers, pager behavior, or packaging:

1. Run focused tests for the touched subsystem.
2. Run the full test suite.
3. Run architecture metrics and inspect new cycles, hub growth, and
   security-surface changes.
4. Run package/version alignment tests.
5. Build release packages when release metadata or install paths changed.
6. Update changelog entries with impact labels.
