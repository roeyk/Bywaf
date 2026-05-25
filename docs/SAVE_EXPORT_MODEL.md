# Save, Export, Archive, And Import

Bywaf uses file verbs by intent rather than by file extension. This keeps
command families predictable as more commandlets grow their own persistence and
handoff behavior.

## Verb Rules

| Verb | Meaning | Typical Audience | Re-importable? |
| --- | --- | --- | --- |
| `save` | Write operator-owned text/configuration so it can be reused or edited. | Operator | Usually yes |
| `load` | Read an operator-owned or runtime resource into the current session. | Operator | Yes |
| `export` | Materialize Bywaf-managed data or evidence onto the filesystem. | Operator, client, tooling | Sometimes |
| `import` | Add external material into a managed Bywaf store. | Operator, maintainer | Yes |
| `archive` | Package a complete framework-owned unit for preservation or handoff. | Operator, team | Intended to be restorable/inspectable |

Short version:

- Use `save` for editable shell/session resources.
- Use `export` for data that Bywaf already manages internally.
- Use `archive` for complete state packages.
- Use `import`, not `load`, when adding durable external material to a managed
  store such as the keyring.

## Command Meanings

| Command | Verb | What It Writes Or Reads | Why This Verb Fits |
| --- | --- | --- | --- |
| `config save file=...` | `save` | Current variable/configuration state as TOML/JSON or encrypted text. | Config is operator-editable session input. |
| `config load file=...` | `load` | A TOML/JSON config file, plaintext or encrypted. | The file becomes the current session configuration. |
| `history save file=...` | `save` | Current command history. | History is operator text that can be reused or edited. |
| `history load file=...` | `load` | A history file, plaintext or encrypted. | The file becomes the current session history source. |
| `script save file=...` | `save` | Current session commands as a runnable script. | A script is editable operator input. |
| `script load file=...` | `load` | A runnable `.bywaf` command script. | Loading a script executes operator-authored commands. |
| `db export file=...` | `export` | A snapshot of the active event database. | The DB is managed state being materialized outward. |
| `artifact import file=...` | `import` | A filesystem file added to the artifact database. | Import adds external material to a managed store. |
| `artifact attach artifact=... step=...` | `attach` | Existing artifact linked to step/pipeline/job provenance. | Attach creates provenance association. |
| `artifact attach step=... file=...` | `attach` | Convenience form: import a file and attach it immediately. | Common workflow without forcing a separate import step. |
| `artifact export ...` | `export` | Artifact body files from the artifact database. | Artifact bodies are managed records being extracted. |
| `audit export file=...` | `export` | Audit trail output such as JSONL, Markdown, PDF, or SQLite. | Audit output is a durable external record of activity. |
| `bundle export ...` | `export` | A curated evidence bundle file. | The bundle is selected evidence prepared for handoff. |
| `key export ...` | `export` | Public or private key material from the managed key store. | Key material is managed state being written out. |
| `key import ...` | `import` | External key material added to the managed key store. | Import changes durable keyring/trust material. |
| `project export file=...` | `export` | The complete framework-owned project package. | The project is managed state prepared for handoff. |
| `project archive file=...` | `archive` | Same project package, emphasizing preservation. | Archive highlights long-term retention. |
| Planned `project import file=...` | `import` | A packaged project archive added to the local project registry. | Import creates/restores managed project state. |
| `project use name=...` | `use` | An existing local project selected as active. | Use changes the active project without importing files. |

## Why Not `key load`?

`key load` would sound like temporarily opening a key for the current process.
Bywaf keys are durable trust material: adding one changes the managed key set.
That is why the command is `key import`.

Use `key export public ...` when sharing verification material. Treat private
key export as a maintainer operation and protect the resulting file.

## Project Export Versus Audit Export

`project export` and `project archive` preserve the whole Bywaf project state:
main database, artifact database, config, history, SQLite sidecars, and archive
manifest.

`audit export` is narrower. It produces an evidence/provenance record: commands,
events, timestamps, variable snapshots, capability use, notes, and related
runtime metadata. It is for review and reporting, not for resuming a project.

## Project Import Versus Project Use

Planned `project import file=...` should mean: unpack or register a project archive into
Bywaf's project area. It creates or restores a local project from an external
package.

`project use name=...` means: switch to a project that is already present
locally. It does not copy files into the project registry.

`project load` is intentionally not used. "Load" is for runtime resources that
are read into the current session; importing a project changes durable managed
state.

## Artifact Export Versus Bundle Export

`artifact import` reads external files into the artifact database. If you also
know the related step, pipeline, or job, `artifact attach step=... file=...` is a
shortcut that imports and attaches in one command. `artifact attach
artifact=... step=...` links an already-stored artifact to provenance.

`artifact export` writes artifact bodies back to files. It answers: "Give me
this file."

`bundle export` writes a curated evidence set with bundle metadata. It answers:
"Package these selected evidence items for handoff."
