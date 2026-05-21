"""Command-aware completion candidate generation.

Provides the registry/database/spec-driven completion engine that knows how to
complete commandlets, options, resources, variables, and runtime selectors.

Used by:
- bywaf.completion: wraps candidate generation for readline and prompt-toolkit.
- plugin completers: receive runtime context derived from this core."""


from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass

from .config import Settings
from .db import EventStore
from .plugin import CompletionContext
from .registry import PluginRegistry
from .specs import CompletionSpec
from .utils import complete_path

DEFAULT_SETTINGS = Settings()
FRAMEWORK_OPTION_COMPLETIONS = {
    "--from-run": CompletionSpec("run"),
    "--from-pipeline": CompletionSpec("pipeline"),
    "--from-topic": CompletionSpec("topic"),
}
BINARY_OPTION_NAMES = {"listen", "silent"}


@dataclass(slots=True)
class CoreCompleter:
    """Command-aware completion engine backed by specs and runtime state."""

    registry: PluginRegistry
    db: EventStore | None = None
    active_context: str | None = None
    builtins: tuple[str, ...] = (
        "help",
        "?",
        "history",
        "info",
        "jobs",
        "pipelines",
        "cmds",
        "load",
        "plugins",
        "project",
        "prompt",
        "run",
        "runs",
        "save",
        "topics",
        "use",
        "vars",
        "exit",
        "event",
        "events",
        "quit",
        "q",
    )

    def candidates(self, line: str) -> list[str]:
        """Return raw completion candidates for a full input line."""
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        tokens = tokens_after_last_pipe(tokens)
        prefix = "" if line.endswith(" ") else (tokens[-1] if tokens else "")
        base = self.base_candidates(tokens, prefix, line.endswith(" "))
        if prefix == "--":
            return sorted(candidate for candidate in set(base) if candidate.startswith("--"))
        return [
            candidate
            for candidate in sorted(set(base))
            if candidate.startswith(prefix) and candidate != prefix
        ]

    def base_candidates(self, tokens: list[str], prefix: str, ended_with_space: bool) -> list[str]:
        """Return unfiltered candidates for the current token context."""
        root_candidates = [*self.builtins, *self.registry.names()]
        if not tokens or (len(tokens) == 1 and not ended_with_space):
            return root_candidates
        command = tokens[0]
        rest = tokens[1:]
        if command in self.registry.plugins:
            return self.plugin_candidates(command, prefix, rest)
        dispatch = {
            "event": self.event_candidates,
            "events": lambda _prefix: ["tail", "--tail", "last="],
            "history": history_candidates,
            "prompt": lambda _prefix: [],
            "run": self.pipeline_expression_candidates,
            "use": lambda _prefix: ["global", *self.registry.names()],
            "load": self.load_candidates,
            "save": self.save_candidates,
            "vars": self.vars_candidates,
        }
        handler = dispatch.get(command)
        return handler(prefix) if handler is not None else root_candidates

    def plugin_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return candidates owned by a plugin commandlet.

        Completion is intentionally layered: custom plugin hook, option values,
        positional argument specs, then generic framework/plugin metadata. This
        keeps command-specific behavior out of the core completer.
        """
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        plugin = self.registry.get(name)
        variable_candidates = self.plugin_variable_candidates(name, prefix)
        if variable_candidates:
            return variable_candidates
        if "=" in prefix and not prefix.startswith("--"):
            key_value_candidates = self.plugin_key_value_candidates(name, prefix)
            if key_value_candidates:
                return key_value_candidates
        if args and not prefix.startswith("--"):
            previous = args[-2] if prefix and args[-1] == prefix and len(args) >= 2 else args[-1]
            value_candidates = self.plugin_option_value_candidates(name, previous, prefix)
            if value_candidates:
                return value_candidates
        if not prefix.startswith("--"):
            custom_candidates = self.plugin_custom_candidates(name, prefix, args)
            matching_custom_candidates = [candidate for candidate in custom_candidates if candidate.startswith(prefix)]
            if matching_custom_candidates:
                return matching_custom_candidates
        if not prefix.startswith("--"):
            positional_candidates = self.plugin_positional_candidates(name, prefix, args)
            matching_positional_candidates = [candidate for candidate in positional_candidates if candidate.startswith(prefix)]
            if matching_positional_candidates:
                return matching_positional_candidates
        binary_flags = [f"--{option.name}" for option in plugin.spec.options if option_is_binary(option.name)]
        valued_options = [f"{option.name}=" for option in plugin.spec.options if not option_is_binary(option.name)]
        options = ["-h", "--help", *binary_flags]
        options.extend(("--from-run", "--from-pipeline", "--from-topic"))
        if prefix.startswith(".") or "/" in prefix:
            return complete_path(prefix)
        return [*valued_options, *options, *plugin.spec.consumes, *plugin.spec.emits]

    def plugin_variable_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete variable references in positional or key=value arguments."""
        key = ""
        value_prefix = prefix
        if "=" in prefix and not prefix.startswith("--"):
            key, value_prefix = prefix.split("=", 1)
        if not value_prefix.startswith("$"):
            return []
        variable_prefix = value_prefix[1:]
        candidates = variable_reference_candidates(self.registry.varstore.names(), plugin_name, variable_prefix)
        if key:
            return [f"{key}={candidate}" for candidate in candidates]
        return candidates

    def plugin_key_value_candidates(self, plugin_name: str, prefix: str) -> list[str]:
        """Complete explicit `name=value` arguments for valued commandlet options."""
        key, value_prefix = prefix.split("=", 1)
        plugin = self.registry.get(plugin_name)
        for option in plugin.spec.options:
            if option.name != key or option_is_binary(option.name):
                continue
            completion_candidates = self.complete_by_spec(option.completion, value_prefix)
            if completion_candidates:
                return [f"{key}={candidate}" for candidate in completion_candidates]
            candidates = [*option.choices]
            stored = self.registry.varstore.get(f"{plugin_name}.{option.name}")
            if stored:
                candidates.append(stored)
            if option.default:
                candidates.append(option.default)
            return [f"{key}={candidate}" for candidate in candidates]
        return []

    def plugin_option_value_candidates(self, plugin_name: str, option_token: str, prefix: str) -> list[str]:
        """Complete a value for a plugin option or framework selector."""
        if option_token in FRAMEWORK_OPTION_COMPLETIONS:
            return self.complete_by_spec(FRAMEWORK_OPTION_COMPLETIONS[option_token], prefix)
        if not option_token.startswith("--"):
            return []
        option_name = option_token[2:]
        plugin = self.registry.get(plugin_name)
        for option in plugin.spec.options:
            if option.name != option_name:
                continue
            completion_candidates = self.complete_by_spec(option.completion, prefix)
            if completion_candidates:
                return completion_candidates
            candidates = [*option.choices]
            stored = self.registry.varstore.get(f"{plugin_name}.{option.name}")
            if stored:
                candidates.append(stored)
            if option.default:
                candidates.append(option.default)
            return candidates
        return []

    def plugin_custom_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Ask a plugin's optional `complete()` hook for candidates."""
        plugin = self.registry.get(plugin_name)
        completer = getattr(plugin, "complete", None)
        if completer is None:
            return []
        context = CompletionContext(
            db=self.db,
            varstore=self.registry.varstore,
            metadata={"commandlets": tuple(self.registry.names())},
        )
        candidates = completer(context, args, prefix)
        return list(candidates) if candidates else []

    def plugin_positional_candidates(self, plugin_name: str, prefix: str, args: list[str]) -> list[str]:
        """Complete the current positional argument from CommandSpec metadata."""
        plugin = self.registry.get(plugin_name)
        position = positional_index(args, prefix)
        if position >= len(plugin.spec.arguments):
            return []
        return self.complete_by_spec(plugin.spec.arguments[position].completion, prefix)

    def topic_candidates(self) -> list[str]:
        """Return topic-like candidates from plugin specs and the active DB."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        job_candidates = [f"job={row['id']}" for row in self.db.jobs()] if self.db else []
        return [*plugin_topics, *db_topics, *job_candidates]

    def event_candidates(self, prefix: str) -> list[str]:
        """Complete `event` selectors and selector values."""
        selectors = ("job=", "run=", "pipeline=", "serial=", "topic=")
        for selector in selectors:
            if prefix.startswith(selector):
                value_prefix = prefix.split("=", 1)[1]
                kind = selector[:-1]
                return [f"{selector}{value}" for value in self.complete_by_spec(CompletionSpec(kind), value_prefix)]
        if prefix:
            selector_matches = [selector for selector in selectors if selector.startswith(prefix)]
            if selector_matches:
                return selector_matches
        return [*self.topic_candidates(), *selectors]

    def run_candidates(self) -> list[str]:
        """Complete command run IDs from the active database."""
        if not self.db:
            return []
        return [row["command_run_id"] for row in self.db.runs()]

    def pipeline_candidates(self) -> list[str]:
        """Complete pipeline IDs from the active database."""
        if not self.db:
            return []
        return sorted({row["pipeline_id"] for row in self.db.runs() if row["pipeline_id"]})

    def run_alias_candidates(self) -> list[str]:
        """Complete user-facing run IDs."""
        if not self.db:
            return []
        return list(self.db.run_aliases().values())

    def pipeline_alias_candidates(self) -> list[str]:
        """Complete user-facing pipeline IDs."""
        if not self.db:
            return []
        return list(self.db.pipeline_aliases().values())

    def serial_candidates(self) -> list[str]:
        """Complete durable serial values."""
        if not self.db:
            return []
        return self.db.serials()

    def job_candidates(self) -> list[str]:
        """Complete job IDs from the active database."""
        if not self.db:
            return []
        return [str(row["id"]) for row in self.db.jobs()]

    def pipeline_expression_candidates(self, prefix: str) -> list[str]:
        """Complete commandlet names after the built-in `run` command."""
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        if prefix.startswith(".") or "/" in prefix:
            return complete_path(prefix)
        return self.registry.names()

    def complete_by_spec(self, spec: CompletionSpec, prefix: str) -> list[str]:
        """Resolve a CompletionSpec into concrete candidates."""
        dispatch = {
            "path": lambda: complete_path(prefix or "."),
            "file": lambda: complete_path(prefix or "."),
            "directory": lambda: complete_path(prefix or "."),
            "choice": lambda: list(spec.values),
            "topic": self.topic_completion_candidates,
            "run": self.run_alias_candidates,
            "pipeline": self.pipeline_alias_candidates,
            "job": self.job_candidates,
            "serial": self.serial_candidates,
            "bundle": lambda: bundle_candidates(self.db),
            "key.any": key_candidates,
            "key.signing": lambda: key_candidates(signing=True),
            "key.verify": lambda: key_candidates(verify=True),
            "plugin": self.registry.names,
        }
        handler = dispatch.get(spec.kind)
        return handler() if handler is not None else []

    def topic_completion_candidates(self) -> list[str]:
        """Complete topic names without selector/job decorations."""
        plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
        db_topics = set(self.db.topics()) if self.db else set()
        return [*plugin_topics, *db_topics]

    def load_candidates(self, prefix: str) -> list[str]:
        """Complete `load` resource keys and values."""
        return resource_candidates(prefix, ("--force", "config=", "db=", "history=", "plugin=", "script="))

    def save_candidates(self, prefix: str) -> list[str]:
        """Complete `save` resource keys and values."""
        return resource_candidates(prefix, ("config=", "db=", "history="))

    def vars_candidates(self, prefix: str) -> list[str]:
        """Complete variables, preferring the active `use` context."""
        names = list(self.registry.varstore.names())
        if "." in prefix or prefix.startswith("global."):
            return [f"{name}=" for name in names]
        if self.active_context:
            scoped_prefix = f"{self.active_context}."
            short_names = [
                f"{name.removeprefix(scoped_prefix)}="
                for name in names
                if name.startswith(scoped_prefix)
            ]
            if short_names:
                return short_names
        namespaces = sorted({name.split(".", 1)[0] for name in names if "." in name})
        return [f"{namespace}." for namespace in namespaces] + [f"{name}=" for name in names if "." not in name]

    def completion_meta(self, candidate: str, line: str, prefix: str) -> str:
        """Return prompt-toolkit metadata for runtime entity completions."""
        if self.db is None:
            return ""
        kind, value = runtime_completion_target(candidate, line, prefix)
        if kind is None:
            return ""
        dispatch = {
            "job": self.job_completion_meta,
            "pipeline": self.pipeline_completion_meta,
            "run": self.run_completion_meta,
        }
        handler = dispatch.get(kind)
        return handler(value) if handler is not None else ""

    def job_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one job completion."""
        if self.db is None:
            return ""
        try:
            row = self.db.job(int(value))
        except ValueError:
            return ""
        if row is None:
            return ""
        artifacts = self.db.artifact_counts_by_job().get(str(row["id"]), 0)
        return f"serial={row['serial']} status={row['status']} artifacts={artifacts} command={row['command_line']}"

    def run_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one run completion."""
        if self.db is None:
            return ""
        serial = self.db.resolve_run_serial(value)
        artifacts = self.db.artifact_counts_by_run().get(serial, 0)
        for row in self.db.runs(active_only=False):
            if row["command_run_id"] == serial:
                return f"serial={serial} source={row['source']} artifacts={artifacts} events={row['events']}"
        return ""

    def pipeline_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one pipeline completion."""
        if self.db is None:
            return ""
        serial = self.db.resolve_pipeline_serial(value)
        artifacts = self.db.artifact_counts_by_pipeline().get(serial, 0)
        for row in self.db.pipelines(active_only=False):
            if row["pipeline_id"] == serial:
                return f"serial={serial} artifacts={artifacts} runs={row['runs']} events={row['events']}"
        return ""


def key_candidates(*, signing: bool = False, verify: bool = False) -> list[str]:
    """Return key names for completion without making cryptography mandatory."""
    try:
        from .keyring import load_key_records, signing_key_names, verification_key_names
    except Exception:
        return []
    try:
        if signing:
            return signing_key_names()
        if verify:
            return verification_key_names()
        return [record.name for record in load_key_records()]
    except Exception:
        return []


def bundle_candidates(db: EventStore | None) -> list[str]:
    """Return known bundle names for completion."""
    if db is None:
        return []
    try:
        return sorted(
            {
                str(event.payload["name"])
                for event in db.events_matching(topic="bundle.created", limit=100000)
                if "name" in event.payload
            }
        )
    except Exception:
        return []


def runtime_completion_target(candidate: str, line: str, prefix: str) -> tuple[str | None, str]:
    """Infer whether a completion candidate represents a job, run, or pipeline."""
    for kind in ("job", "run", "pipeline"):
        selector = f"{kind}="
        if candidate.startswith(selector):
            return kind, candidate.removeprefix(selector)
        if prefix.startswith(selector):
            return kind, candidate
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    tokens = tokens_after_last_pipe(tokens)
    if len(tokens) >= 2 and tokens[0] == "pipeline" and tokens[1] in {"attach", "show", "cancel", "end", "kill"}:
        return "pipeline", candidate
    if len(tokens) >= 2 and tokens[0] == "job" and tokens[1] in {"show", "cancel", "end", "kill"}:
        return "job", candidate
    return None, candidate


def option_is_binary(option_name: str) -> bool:
    """Return whether an option should complete as a binary `--flag`."""
    return option_name in BINARY_OPTION_NAMES


def variable_reference_candidates(names: Sequence[str], commandlet: str, prefix: str) -> list[str]:
    """Return `$variable` completions using commandlet and global shorthand."""
    candidates: set[str] = set()
    commandlet_prefix = f"{commandlet}."
    for name in names:
        if name.startswith(commandlet_prefix):
            candidates.add(f"${name.removeprefix(commandlet_prefix)}")
        if name.startswith("global."):
            candidates.add(f"${name.removeprefix('global.')}")
        candidates.add(f"${{{name}}}")
        if "." not in name:
            candidates.add(f"${name}")
    full_prefix = f"${prefix}"
    return sorted(candidate for candidate in candidates if candidate.startswith(full_prefix))


def resource_candidates(prefix: str, keywords: tuple[str, ...]) -> list[str]:
    """Complete key=value resource expressions used by load/save."""
    for keyword in keywords:
        if keyword.endswith("=") and prefix.startswith(keyword):
            value = prefix.split("=", 1)[1]
            return [f"{keyword}{path}" for path in complete_resource_value(keyword[:-1], value)]
    keyword_matches = [keyword for keyword in keywords if keyword.startswith(prefix)]
    if keyword_matches:
        return keyword_matches
    if prefix:
        return complete_path(prefix)
    return list(keywords)


def complete_at_file_prefix(prefix: str) -> list[str]:
    """Complete framework at-file path prefixes while preserving operators."""
    if prefix.startswith("@@"):
        value = prefix[2:]
        return [f"@@{candidate}" for candidate in complete_path(value)]
    for operator in ("@lines:", "@raw:"):
        if prefix.startswith(operator):
            value = prefix.removeprefix(operator)
            return [f"{operator}{candidate}" for candidate in complete_path(value)]
    value = prefix.removeprefix("@")
    return [f"@{candidate}" for candidate in complete_path(value)]


def complete_resource_value(kind: str, value: str) -> list[str]:
    """Complete the value side of a load/save resource expression."""
    if is_explicit_path(value):
        return preserve_explicit_prefix(value, complete_path(value or "."))
    if kind == "plugin":
        return complete_path(value, DEFAULT_SETTINGS.plugin_dir)
    return complete_path(value)


def positional_index(args: list[str], prefix: str) -> int:
    """Return the positional argument index currently being completed."""
    if not args:
        return 0
    positional = [
        arg for arg in args
        if not arg.startswith("-") and arg not in {"|", "&"}
    ]
    if prefix and positional and positional[-1] == prefix:
        return len(positional) - 1
    return len(positional)


def is_explicit_path(value: str) -> bool:
    """Return True when a resource value should be treated as a path."""
    return value.startswith(("./", "../", "~/", "/"))


def preserve_explicit_prefix(value: str, candidates: list[str]) -> list[str]:
    """Keep leading `./` visible so readline replaces the token correctly."""
    if value.startswith("./"):
        return [candidate if candidate.startswith("./") else f"./{candidate}" for candidate in candidates]
    return candidates


def tokens_after_last_pipe(tokens: list[str]) -> list[str]:
    """Return tokens belonging to the command after the last pipeline marker."""
    if "|" not in tokens:
        return tokens
    last_pipe = len(tokens) - 1 - tokens[::-1].index("|")
    return tokens[last_pipe + 1 :]


def history_candidates(prefix: str) -> list[str]:
    """Complete timestamp-window selectors for the built-in history command."""
    selectors = ("since=", "until=")
    return [selector for selector in selectors if selector.startswith(prefix)]
