# Writing Bywaf Plugins

The plugin author documentation now lives in [docs/plugin_author/](plugin_author/README.md).

Current Bywaf plugins are commandlets, not Veil modules, Metasploit modules,
`info` dictionaries, or `run/exploit` scripts.

Current API at a glance:

```text
plugin.py          decorated CommandletBase class plus plugin() factory
command.py         runtime parsing, event iteration, context interaction
detect.py          pure detection/protocol logic, testable without Bywaf
findings.py        normalized finding payloads via bywaf.finding helpers
models.py          plugin-local domain objects
bywaf.plugin.toml  sidecar manifest contract for capabilities and traits
```

Start with:

1. [Plugin Author Guide](plugin_author/README.md)
2. [Plugin Fundamentals](plugin_author/fundamentals.md)
3. [Commandlet API Reference](plugin_author/commandlet-api.md)
4. [Plugin Packaging And Checking](plugin_author/packaging-and-checking.md)

For vulnerability or CVE checks, also read [Vulnerability Plugins](plugin_author/vulnerability-plugins.md) and [Plugin Skeletons](plugin_skeletons/README.md).
