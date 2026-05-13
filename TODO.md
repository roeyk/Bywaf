# TODO

Planning dates are release planning markers, not compatibility commitments.

## Current Release

- Bywaf 0.9.0 testing release: 2026-05-13.

## Target: 0.10.0

### Framework-Owned Paging

- Add a framework request/API such as `context.page_file(path)`.
- Have `less` request paging instead of launching the system pager directly.
- Let the terminal REPL handle the request by opening `less` when interactive.
- Let noninteractive, GUI, and web frontends handle the same request by rendering
  file content in their own output/view layer.
