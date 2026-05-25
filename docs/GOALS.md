# Bywaf Project Goals

## 1. Make security workflows fast and convenient

Bywaf should reduce the friction of common assessment workflows. The user should be able to move from discovery to analysis to reporting without constantly switching tools, copying output, or manually transforming data.

Convenience and operational continuity are important goals of the framework. Users should be able to:

- pause and resume jobs;
- pause and resume pipelines;
- inspect current runtime state;
- reconnect to long-running workflows;
- and continue assessments without losing intermediate work.

The framework should support long-running and interruptible audit workflows cleanly.

---

## 2. Remain flexible and leverage existing tools

Bywaf should integrate cleanly with existing security tools, libraries, and workflows whenever practical instead of unnecessarily reinventing mature functionality.

Metasploit is an important point of comparison because it already provides an
interactive security console, a large module ecosystem, sessions, jobs, and
well-established pentest workflows. Bywaf should not try to win by imitating
Metasploit feature-for-feature. Its goal is to occupy a related but distinct
space: highly auditable event-driven orchestration, pipeline composition, and
Python-first plugin ergonomics over normalized assessment data.

The overlap is intentional at the user-interface level. A Metasploit-like shell
is familiar to operators, and that familiarity lowers the cost of adoption.
The difference should be visible in what happens after commands run: Bywaf
should preserve durable provenance, expose structured event flows, make
intermediate results reusable by later commandlets, and keep enough audit data
for replay, reporting, and review.

In practice, this means Bywaf can wrap tools that overlap with Metasploit,
including scanners and exploit-support utilities, but the framework's central
value is coordination and traceability rather than replacing every mature tool.
Where Metasploit is strongest as an exploitation framework, Bywaf should be
strongest as an auditable workflow framework that lets discovery, analysis,
artifact capture, and reporting steps cooperate without manual handoffs.

The framework should support:

- subprocess-based tool wrappers;
- library-backed integrations;
- pure framework-native plugins;
- and native-code integrations.

Bywaf should act as an orchestration and normalization layer that allows existing tools to cooperate through structured events and pipelines.

The framework should favor:

- reusable integrations;
- normalized event schemas;
- composable workflows;
- and interoperability between tools.

Mature external tools should be leveraged where they provide substantial capability, protocol knowledge, ecosystem support, or operational maturity that would be difficult or wasteful to reproduce inside the framework.

---

## 3. Make plugin writing easy

A useful plugin should be easy to write, easy to test, and easy to document. Plugin authors should not need to understand the full framework internals just to create:

- commandlets;
- listeners;
- renderers;
- scanners;
- analyzers;
- exporters;
- or services.

The framework should provide:

- clear plugin APIs;
- stable event schemas;
- straightforward capability declarations;
- and strong documentation.

---

## 4. Remove manual handoffs between pipeline steps

Bywaf should eliminate manual copy/paste workflows between tools.

Instead of:

```text
run host discovery
copy live hosts into a file
feed file into port scanner
copy open ports elsewhere
feed results into web scanner
```

Bywaf should allow:

```text
host discovery
    ->
port scanning
    ->
service detection
    ->
HTTP discovery
    ->
screenshots
    ->
findings
    ->
reports
```

with structured events flowing automatically between steps.

Intermediate results should remain durable, queryable, and reusable.

---

## 5. Provide robust documentation

Documentation is a core part of the framework, not an afterthought.

Bywaf should provide clear onboarding for:

- users;
- plugin authors;
- contributors;
- operators;
- and maintainers.

Documentation should explain:

- how the framework works;
- how concepts relate;
- how plugins integrate;
- how events flow;
- and why architectural decisions exist.

Important architectural and conceptual documents may include:

- `EVENT_MODEL.md`
- `RUNTIME_MODEL.md`
- `CAPABILITY_MODEL.md`
- `TERMINOLOGY.md`
- `SYSTEM_BLOCK_DIAGRAM.pdf`
- `SYSTEM_DATAFLOW_DIAGRAM.pdf`
- future `PLUGIN_TYPES.md`
- future `PLUGIN_SECURITY_MODEL.md`
- future `COMMAND_SYNTAX.md`

The project should emphasize strong terminology and stable conceptual definitions.

---

## 6. Guarantee auditability and traceability

Bywaf should preserve a durable, inspectable history of:

- pipeline steps;
- jobs;
- pipelines;
- events;
- findings;
- capability usage;
- plugin activity;
- framework actions;
- and intermediate results.

Users should be able to determine:

- what happened;
- when it happened;
- what produced a result;
- what inputs were used;
- and how conclusions were reached.

This includes:

- append-only event storage;
- durable event persistence;
- capability audit logs;
- replay semantics;
- reproducible workflows;
- and queryable historical state.

Audit records should be easy to extract for review and handoff. Users should be
able to filter audit logs by date/time ranges and export the selected records
to plain text, structured text formats, or PDF. PDF exports should optionally
support encryption so sensitive assessment records can be shared or archived
without leaving plaintext reports behind.

Findings should never depend solely on:

- terminal scrollback;
- ephemeral memory;
- or manually copied notes.

---

# Architectural Principles

## Events are canonical

Structured events are primary artifacts of the framework, not temporary transport mechanisms.

Console rendering, reports, dashboards, and other interfaces should derive from canonical event data.

---

## Normalize outputs aggressively

Plugins should emit normalized events whenever possible.

The framework should avoid treating raw tool output as the primary long-term interface.

---

## Preserve conceptual clarity

The framework should maintain precise terminology and stable architectural concepts.

Examples include:

- commandlet;
- internal command;
- job;
- pipeline step;
- pipeline;
- listener;
- service;
- event;
- topic;
- and capability.

Stable terminology reduces architectural drift and improves:

- usability;
- maintainability;
- plugin interoperability;
- documentation quality;
- and AI-assisted development.
