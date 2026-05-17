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

## 4. Remove manual handoffs between pipeline stages

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

with structured events flowing automatically between stages.

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

- `ARCHITECTURE.md`
- `EVENT_MODEL.md`
- `RUNTIME_MODEL.md`
- `CAPABILITY_MODEL.md`
- `TERMINOLOGY.md`
- `PLUGIN_TYPES.md`
- `PLUGIN_SECURITY_MODEL.md`
- `COMMAND_SYNTAX.md`

The project should emphasize strong terminology and stable conceptual definitions.

---

## 6. Guarantee auditability and traceability

Bywaf should preserve a durable, inspectable history of:

- runs;
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
- run;
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

