# Output Subjects And Theme Styles

Plugins should emit structured payloads and describe important values with
subjects. A subject says what a value is about, such as `host`, `port`, `path`,
`username`, `finding.title`, or `evidence`. It is not a color, a Python type,
or an access-control role.

Renderers use subjects to apply the operator's theme. This keeps plugins from
hard-coding terminal colors while still letting reports, event listings, and
future interfaces highlight security-relevant fields consistently.

## Authoring Rule

For vulnerability plugins, prefer the normalized finding helpers:

```python
from bywaf.finding import candidate_payload, subject_value

payload = candidate_payload(
    title="Exposed Git repository configuration",
    finding_class="web.exposure.git_config",
    target={"host": "example.test", "path": "/.git/config"},
    affected=[{"url": "https://example.test/.git/config"}],
    evidence=subject_value("evidence", "returned Git configuration content"),
    severity="high",
)
```

`candidate_payload(...)` infers common subjects from canonical field names. Use
`subject_value(subject, value)` when the field name is ambiguous, or pass an
explicit `subjects={"payload.path": "subject"}` map when needed.

## Style Resolution

Theme files set display variables. The renderer looks up subject styles with the
`display/style.` prefix:

```toml
[variables]
"display/style.host" = "bold green"
"display/style.port" = "yellow"
"display/style.path" = "cyan"
"display/style.finding.title" = "bold white"
"display/style.finding.severity.high" = "bold red"
```

Theme files may also use structured style tables. This is equivalent to the
compact string form, but easier to read for styles with both foreground and
background colors:

```toml
[variables."display/style.host"]
foreground = "cyan"
background = "transparent"
bold = true

[variables."display/style.finding.severity_class.emergency"]
foreground = "white"
background = "ansi:52"
bold = true
```

`background = "transparent"` means the subject does not set its own background;
an enclosing table or report style can continue to show through. The same
structured fields can be set directly as preferences or variables, for example
`display/style.host.foreground=cyan` and
`display/style.host.background=transparent`.

Subject styles are semantic overrides. Broad styles provide a baseline, and more
specific subjects win inside that baseline. For example:

- a table body cell may use `display/style.table.body`
- a host value inside that cell may use `display/style.host`
- a quoted string may use `display/style.string`
- a `$VARIABLE` inside that string may use `display/style.variable`

This means plugin authors should describe payload values, not presentation.
Theme authors decide what those descriptions look like.

## Common Subjects

Common subjects include:

| Subject | Use for |
| --- | --- |
| `host` / `ip` | IP addresses and host identifiers |
| `port` | TCP/UDP port numbers |
| `protocol` | Protocol names such as `tcp`, `udp`, `http`, `https` |
| `url` / `path` | Full URLs, HTTP paths, filesystem paths, or cloud object paths |
| `username` / `account` / `email` | Identity-related values |
| `service` | Service names such as `ssh`, `telnet`, `http` |
| `timestamp` | Operator-facing timestamps |
| `serial` | Durable runtime or artifact serials |
| `job` / `step` / `pipeline` | Runtime provenance identifiers |
| `command_line` | Commands shown for rerun, inspection, provenance, or follow-up actions |
| `comment` | Human comments and inline notes |
| `string` / `value` / `variable` | REPL syntax highlighting subjects |
| `cve` / `cwe` | Vulnerability identifiers |
| `severity` | Severity labels |
| `finding.title` | Finding title text |
| `finding.class` | Bywaf finding class strings |
| `finding.status` | Finding lifecycle status |
| `evidence` / `explanation` | Evidence snippets and explanatory vulnerability text |
| `artifact` | Artifact IDs, names, or paths |

## Table And Report Styles

Renderers should use table styles as defaults and semantic subjects as overrides:

```toml
[variables]
"display/style.table.header" = "bold white"
"display/style.table.body" = "color250"
"display/style.table.index" = "bold color245"
"display/style.table.active_row" = "bold"
"display/style.table.active_column" = "bold white"
"display/style.report.heading" = "bold color39"
"display/style.report.section" = "bold white"
"display/style.report.label" = "bold color245"
"display/style.serial" = "color245"
"display/style.command_line" = "cyan"
"display/style.job" = "color39"
"display/style.step" = "color39"
"display/style.pipeline" = "color39"
"display/style.finding.severity_class.urgent" = "bold red"
"display/style.finding.severity_class.emergency" = "bold white bg-ansi:52"
```

The same emergency style can be written with explicit foreground/background
fields:

```toml
[variables."display/style.finding.severity_class.emergency"]
foreground = "white"
background = "ansi:52"
bold = true
```

Table/report styles are renderer-owned presentation defaults. Plugin payloads
should still use subjects such as `host`, `path`, `finding.title`, and
`evidence` so those values can stand out wherever they appear.

Reports derive severity classes from the normalized `severity` value. Plugins
should continue emitting `severity=info|low|medium|high|critical`; report
renderers map those values to operational classes for summary and styling:

| Severity | Severity class |
| --- | --- |
| `info` | `informational` |
| `low` | `advisory` |
| `medium` | `review` |
| `high` | `urgent` |
| `critical` | `emergency` |
