"""Readline-compatible completion helpers."""

from __future__ import annotations

import readline
import shlex
from os.path import commonprefix
from collections.abc import Sequence
from dataclasses import dataclass

from .config import Settings
from .db import EventStore
from .plugin import CompletionContext, CompletionSpec
from .registry import PluginRegistry
from .utils import complete_path

DEFAULT_SETTINGS = Settings()
FRAMEWORK_OPTION_COMPLETIONS = {
    "--from-run": CompletionSpec("run"),
    "--from-pipeline": CompletionSpec("pipeline"),
    "--from-topic": CompletionSpec("topic"),
}


@dataclass(slots=True)
class Completer:
    """Readline completer backed by command specs and runtime state."""

    registry: PluginRegistry
    db: EventStore | None = None
    builtins: tuple[str, ...] = (
        "help",
        "?",
        "history",
        "jobs",
        "pipelines",
        "cmds",
        "load",
        "plugins",
        "prompt",
        "repl",
        "run",
        "runs",
        "save",
        "show",
        "topics",
        "vars",
        "exit",
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
        match tokens:
            case []:
                base = [*self.builtins, *self.registry.names()]
            case [_] if not line.endswith(" "):
                base = [*self.builtins, *self.registry.names()]
            case ["show", *_]:
                base = self.show_candidates(prefix)
            case [name, *rest] if name in self.registry.plugins:
                base = self.plugin_candidates(name, prefix, rest)
            case ["load", *_]:
                base = self.load_candidates(prefix)
            case ["save", *_]:
                base = self.save_candidates(prefix)
            case ["vars", *_]:
                base = [f"{name}=" for name in self.registry.varstore.names()]
            case _:
                base = [*self.builtins, *self.registry.names()]
        if prefix == "--":
            return sorted(candidate for candidate in set(base) if candidate.startswith("--"))
        return [
            candidate
            for candidate in sorted(set(base))
            if candidate.startswith(prefix) and candidate != prefix
        ]

    def plugin_candidates(self, name: str, prefix: str, args: list[str]) -> list[str]:
        """Return candidates owned by a plugin commandlet.

        Completion is intentionally layered: custom plugin hook, option values,
        positional argument specs, then generic framework/plugin metadata. This
        keeps command-specific behavior out of the core completer.
        """
        if prefix.startswith("@"):
            return complete_at_file_prefix(prefix)
        plugin = self.registry.get(name)
        if not prefix.startswith("--"):
            custom_candidates = self.plugin_custom_candidates(name, prefix, args)
            if custom_candidates:
                return custom_candidates
        if args and not prefix.startswith("--"):
            previous = args[-2] if prefix and args[-1] == prefix and len(args) >= 2 else args[-1]
            value_candidates = self.plugin_option_value_candidates(name, previous, prefix)
            if value_candidates:
                return value_candidates
        if not prefix.startswith("--"):
            positional_candidates = self.plugin_positional_candidates(name, prefix, args)
            if positional_candidates:
                return positional_candidates
        options = ["-h", "--help", *[f"--{option.name}" for option in plugin.spec.options]]
        options.extend(("--from-run", "--from-pipeline", "--from-topic"))
        if prefix.startswith(".") or "/" in prefix:
            return complete_path(prefix)
        return [*options, *plugin.spec.consumes, *plugin.spec.emits]

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

    def show_candidates(self, prefix: str) -> list[str]:
        """Complete `show` selectors and selector values."""
        selectors = ("job=", "run=", "pipeline=", "topic=")
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

    def job_candidates(self) -> list[str]:
        """Complete job IDs from the active database."""
        if not self.db:
            return []
        return [str(row["id"]) for row in self.db.jobs()]

    def complete_by_spec(self, spec: CompletionSpec, prefix: str) -> list[str]:
        """Resolve a CompletionSpec into concrete candidates."""
        match spec.kind:
            case "path" | "file" | "directory":
                return complete_path(prefix or ".")
            case "choice":
                return list(spec.values)
            case "topic":
                plugin_topics = {topic for plugin in self.registry.plugins.values() for topic in plugin.spec.emits}
                db_topics = set(self.db.topics()) if self.db else set()
                return [*plugin_topics, *db_topics]
            case "run":
                return self.run_candidates()
            case "pipeline":
                return self.pipeline_candidates()
            case "job":
                return self.job_candidates()
            case "plugin":
                return self.registry.names()
            case _:
                return []

    def load_candidates(self, prefix: str) -> list[str]:
        """Complete `load` resource keys and values."""
        return resource_candidates(prefix, ("config=", "db=", "history=", "plugin=", "script="))

    def save_candidates(self, prefix: str) -> list[str]:
        """Complete `save` resource keys and values."""
        return resource_candidates(prefix, ("config=", "db=", "history="))

    def complete(self, text: str, state: int) -> str | None:
        """Readline callback: return one candidate per requested state."""
        line = readline.get_line_buffer()
        candidates = self.candidates(line)
        common = common_completion_prefix(line, candidates)
        if state == 0 and common:
            return common
        if state == 0 and should_print_completion_menu(line, candidates):
            print_completion_menu(line, candidates)
            return None
        results = completion_results(line, candidates)
        return results[state] if state < len(results) else None

    def format_candidate(self, candidate: str) -> str:
        if candidate.startswith("--") or candidate.endswith("=") or candidate.endswith("/"):
            return candidate
        return candidate + " "

    def format_common_prefix(self, candidate: str) -> str:
        return candidate


def resource_candidates(prefix: str, keywords: tuple[str, ...]) -> list[str]:
    """Complete key=value resource expressions used by load/save."""
    for keyword in keywords:
        if prefix.startswith(keyword):
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
    match kind:
        case "plugin":
            return complete_path(value, DEFAULT_SETTINGS.plugin_dir)
        case "script" | "db" | "config" | "history":
            return complete_path(value)
        case _:
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


def install_readline(completer: Completer) -> None:
    """Install a Completer into Python readline."""
    configure_readline_delimiters()
    readline.set_completer(completer.complete)
    readline.parse_and_bind("tab: complete")


def configure_readline_delimiters() -> None:
    """Keep option dashes and key/value equals signs inside completion tokens."""
    delimiters = readline.get_completer_delims()
    readline.set_completer_delims(delimiters.replace("-", "").replace("=", ""))


def tokens_after_last_pipe(tokens: list[str]) -> list[str]:
    """Return tokens belonging to the command after the last pipeline marker."""
    if "|" not in tokens:
        return tokens
    last_pipe = len(tokens) - 1 - tokens[::-1].index("|")
    return tokens[last_pipe + 1 :]


def should_print_completion_menu(line: str, candidates: Sequence[str]) -> bool:
    """Use a custom menu for key=value completions so labels stay readable."""
    prefix = completion_prefix(line)
    return (
        len(candidates) > 1
        and "=" in prefix
        and all(candidate.startswith(prefix.split("=", 1)[0] + "=") for candidate in candidates)
    )


def print_completion_menu(line: str, candidates: Sequence[str]) -> None:
    """Print value-only labels for key=value completion candidates."""
    labels = [display_label(candidate) for candidate in candidates]
    print()
    print("  " + "   ".join(labels))
    print(line, end="", flush=True)


def display_label(candidate: str) -> str:
    """Strip key prefixes from key=value candidates for display."""
    if "=" in candidate:
        return candidate.split("=", 1)[1]
    return candidate


def completion_prefix(line: str) -> str:
    """Return the current token prefix from a readline buffer."""
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    tokens = tokens_after_last_pipe(tokens)
    return "" if line.endswith(" ") else (tokens[-1] if tokens else "")


def completion_results(line: str, candidates: Sequence[str]) -> list[str]:
    """Return readline-formatted completion results."""
    common = common_completion_prefix(line, candidates)
    if common:
        return [common, *[format_candidate(candidate) for candidate in candidates]]
    return [format_candidate(candidate) for candidate in candidates]


def common_completion_prefix(line: str, candidates: Sequence[str]) -> str | None:
    """Return a shared candidate prefix that extends the current token."""
    prefix = completion_prefix(line)
    if len(candidates) < 2:
        return None
    common = commonprefix(list(candidates))
    if len(common) > len(prefix):
        return common
    if "=" in prefix:
        key = prefix.split("=", 1)[0] + "="
        if all(candidate.startswith(key) for candidate in candidates):
            suffix_common = commonprefix([candidate[len(key):] for candidate in candidates])
            if len(suffix_common) > len(prefix[len(key):]):
                return key + suffix_common
    return None


def format_candidate(candidate: str) -> str:
    """Append spaces only to complete word-like candidates."""
    if candidate.startswith("--") or candidate.endswith("=") or candidate.endswith("/"):
        return candidate
    return candidate + " "
