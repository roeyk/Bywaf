# TODO

## Framework-Owned Paging

- Add a framework request/API such as `context.page_file(path)`.
- Have `less` request paging instead of launching the system pager directly.
- Let the terminal REPL handle the request by opening `less` when interactive.
- Let noninteractive, GUI, and web frontends handle the same request by rendering
  file content in their own output/view layer.
