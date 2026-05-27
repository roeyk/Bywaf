#set page(width: 11in, height: 8.5in, margin: 0.45in)
#set text(font: "DejaVu Sans", size: 9.2pt)

#let box(title, body, fill: rgb("#f7f7f7")) = rect(
  width: 100%,
  inset: 7pt,
  radius: 2pt,
  stroke: rgb("#334155"),
  fill: fill,
)[
  #strong(title)
  #v(4pt)
  #body
]

#let arrow(label) = align(center)[
  #text(size: 13pt)[=>]
  #v(1pt)
  #text(size: 7.2pt)[#label]
]

= Bywaf System Dataflow Diagram

#text(size: 8.4pt)[This diagram focuses on data movement and durable records. It complements `SYSTEM_BLOCK_DIAGRAM.pdf`, which focuses on major system components.]

#v(8pt)

#grid(
  columns: (1.15fr, 0.28fr, 1.25fr, 0.28fr, 1.25fr, 0.28fr, 1.25fr),
  gutter: 6pt,
  align: horizon,
  box("User Input", [
    REPL commands \
    scripts \
    inline variables \
    `@file` arguments \
    `note=` and names
  ], fill: rgb("#fff8e8")),
  arrow("parsed"),
  box("Command Normalization", [
    line continuations \
    semicolon splitting \
    pipeline splitting \
    variable expansion \
    at-file expansion
  ], fill: rgb("#edf7ff")),
  arrow("creates"),
  box("Runtime Records", [
    job row + serial \
    pipeline row + serial \
    step row + serial \
    local numeric aliases \
    variable snapshot
  ], fill: rgb("#edf7ff")),
  arrow("invokes"),
  box("Commandlet Context", [
    args and input events \
    `context.events` \
    `context.process` \
    `context.artifacts` \
    `context.signals`
  ], fill: rgb("#eef9ef")),
)

#v(10pt)

#grid(
  columns: (1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr),
  gutter: 7pt,
  align: horizon,
  box("Normalized Events", [
    `host.found` \
    `port.open` \
    `http.endpoint` \
    findings \
    runtime state
  ], fill: rgb("#f8f8f8")),
  arrow("scope"),
  box("Event Store", [
    append-only rows \
    topic + payload \
    source \
    pipeline/step/parent \
    timestamp
  ], fill: rgb("#f8f8f8")),
  arrow("feeds"),
  box("Subscribers", [
    downstream pipeline steps \
    late attach/replay \
    reports \
    search \
    future GUI/web views
  ], fill: rgb("#f8f8f8")),
  arrow("outputs"),
  box("Operator Views", [
    console output \
    alerts \
    tables \
    pagers \
    exported reports
  ], fill: rgb("#fff8e8")),
)

#v(10pt)

#grid(
  columns: (1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr, 0.25fr, 1.2fr),
  gutter: 7pt,
  align: horizon,
  box("Framework Requests", [
    output requested \
    alert requested \
    file page requested \
    process run/stream requested \
    prompts/approval
  ], fill: rgb("#f2efff")),
  arrow("validated"),
  box("Policy + Capabilities", [
    `--test` evaluation \
    allow/deny/repair \
    capability used/missing \
    approved_by \
    override notices
  ], fill: rgb("#fff0f0")),
  arrow("records"),
  box("Audit Events", [
    request outcomes \
    policy decisions \
    process stdout/stderr \
    control signals \
    names and notes
  ], fill: rgb("#f8f8f8")),
  arrow("query"),
  box("Audit Export", [
    `audit show` \
    `audit export` \
    since/until filters \
    text/json/sqlite/pdf \
    optional PDF encryption
  ], fill: rgb("#eef9ef")),
)

#v(10pt)

#grid(
  columns: (1.25fr, 0.25fr, 1.25fr, 0.25fr, 1.25fr),
  gutter: 8pt,
  align: horizon,
  box("Artifact Inputs", [
    screenshots \
    copied files \
    command output \
    notes \
    `@file` provenance
  ], fill: rgb("#eef9ef")),
  arrow("attach"),
  box("Artifact Store", [
    optional encryption \
    binary/text content \
    multiple artifacts per entity \
    hashes \
    titles/names and notes
  ], fill: rgb("#f8f8f8")),
  arrow("verify/save/search"),
  box("Artifact Metadata", [
    main DB metadata \
    step/pipeline/job links \
    serials \
    timestamps \
    searchable fields
  ], fill: rgb("#f8f8f8")),
)

#v(10pt)

== Dataflow Guarantees

#grid(
  columns: (1fr, 1fr),
  gutter: 12pt,
  [
    #strong("Durability")
    - Runtime entities receive local IDs and durable serials.
    - Events are stored before they become reusable audit evidence.
    - Artifacts carry hashes in both artifact storage and main metadata.
  ],
  [
    #strong("Traceability")
    - Inputs, variable expansion, and `@file` expansion are auditable.
    - Framework requests produce explicit outcome events.
    - Reports and future frontends derive from events, not terminal scrollback.
  ],
)
