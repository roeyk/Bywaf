#set page(width: 11in, height: 8.5in, margin: 0.45in)
#set text(font: "DejaVu Sans", size: 9.5pt)

#let box(title, body, fill: rgb("#f5f7fb")) = rect(
  width: 100%,
  inset: 8pt,
  radius: 2pt,
  stroke: rgb("#30445c"),
  fill: fill,
)[
  #strong(title)
  #v(4pt)
  #body
]

#let arrow(label) = align(center)[
  #text(size: 14pt)[=>]
  #v(2pt)
  #text(size: 7.5pt)[#label]
]

= Bywaf System Block Diagram

#text(size: 8.5pt)[This diagram shows both live runtime flow and durable data flow. Live command execution moves left to right; audit, event, and artifact records flow downward into durable stores.]

#v(8pt)

#grid(
  columns: (1.25fr, 0.35fr, 1.35fr, 0.35fr, 1.45fr, 0.35fr, 1.35fr),
  rows: auto,
  gutter: 7pt,
  align: horizon,
  box("Operator / Frontend", [
    REPL, scripts, future GUI/web \
    completion and help \
    commands, pipelines, selectors
  ], fill: rgb("#fff8e8")),
  arrow("input"),
  box("Framework Shell", [
    parser and completer \
    policy/test handling \
    job, pipeline, run creation \
    request dispatcher
  ], fill: rgb("#edf7ff")),
  arrow("supervises"),
  box("Runtime Supervisor", [
    foreground/background jobs \
    pipeline stages \
    process handles \
    pause/resume/cancel/kill
  ], fill: rgb("#edf7ff")),
  arrow("invokes"),
  box("Commandlet Runs", [
    hostscanner \
    portscanner \
    http_probe \
    OS/runtime/storage plugins
  ], fill: rgb("#eef9ef")),
)

#v(10pt)

#grid(
  columns: (1.45fr, 0.35fr, 1.45fr, 0.35fr, 1.45fr),
  rows: auto,
  gutter: 8pt,
  align: horizon,
  box("Framework APIs", [
    context.events \
    context.output / alert \
    context.process \
    context.artifacts \
    context.signals
  ], fill: rgb("#f2efff")),
  arrow("mediates"),
  box("Policy + Capability Audit", [
    capabilities used/missing \
    --test policy evaluation \
    operator approvals \
    denied/allowed requests
  ], fill: rgb("#fff0f0")),
  arrow("records"),
  box("Framework Request IPC", [
    console output and alerts \
    file paging \
    process execution \
    prompts and future UI actions
  ], fill: rgb("#f2efff")),
)

#v(10pt)

#grid(
  columns: (1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr),
  rows: auto,
  gutter: 7pt,
  align: horizon,
  box("Main SQLite DB", [
    append-only events \
    jobs, pipelines, runs \
    variable snapshots \
    names, notes, policies \
    artifact metadata and hashes
  ], fill: rgb("#f8f8f8")),
  arrow("links"),
  box("Artifact DB", [
    attached evidence \
    screenshots, text, files \
    optional encryption \
    hash verification
  ], fill: rgb("#f8f8f8")),
  arrow("feeds"),
  box("Reports / Exports", [
    audit show/export \
    artifact save/search \
    optional encrypted PDF \
    reproducible handoff
  ], fill: rgb("#f8f8f8")),
  arrow("supports"),
  box("Future Frontends", [
    local GUI \
    web UI \
    dashboards \
    same event/request model
  ], fill: rgb("#fff8e8")),
)

#v(12pt)

== Key Flows

#grid(
  columns: (1fr, 1fr),
  gutter: 12pt,
  [
    #strong("Live runtime flow")
    - Operator submits a command or script.
    - Framework parses, expands, tests policies, and creates runtime IDs.
    - Supervisor invokes commandlet runs in foreground or background.
    - Commandlets use framework APIs for output, events, artifacts, processes, and signals.
  ],
  [
    #strong("Durable audit flow")
    - Runs publish normalized events into SQLite.
    - Framework requests and outcomes are stored as events.
    - Artifacts store content while the main DB stores metadata and hashes.
    - Reports, searches, and future UI views derive from durable records.
  ],
)
