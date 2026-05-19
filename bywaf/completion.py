"""Readline and prompt-toolkit completion helpers."""
# pyright: reportMissingImports=false, reportGeneralTypeIssues=false
# pyright: reportInvalidTypeForm=false

from __future__ import annotations

import readline
import shlex
from os.path import commonprefix
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

try:
    from prompt_toolkit.application.current import get_app
    from prompt_toolkit.completion import Completion
    from prompt_toolkit.completion import Completer as PromptToolkitCompleterBase
    from prompt_toolkit.enums import DEFAULT_BUFFER
    from prompt_toolkit.filters import has_completions
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.shortcuts.prompt import CompleteStyle
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    get_app = None
    Completion = None
    PromptToolkitCompleterBase = object
    DEFAULT_BUFFER = "DEFAULT_BUFFER"
    has_completions = None
    HTML = None
    KeyBindings = None
    PromptSession = None
    CompleteStyle = None

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
BINARY_OPTION_NAMES = {"listen", "silent"}
COMPLETION_SELECT_KEY_VAR = "completion.select-key"
COMPLETION_WASD_SELECTION_VAR = "completion.wasd-selection"
DEFAULT_COMPLETION_SELECT_KEY = "c-space"


@dataclass(slots=True)
class Completer:
    """Readline completer backed by command specs and runtime state."""

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
        match tokens:
            case []:
                base = [*self.builtins, *self.registry.names()]
            case [_] if not line.endswith(" "):
                base = [*self.builtins, *self.registry.names()]
            case ["event", *_]:
                base = self.event_candidates(prefix)
            case ["events", *_]:
                base = ["tail", "--tail", "last="]
            case ["history", *_]:
                base = history_candidates(prefix)
            case ["prompt", *_]:
                base = []
            case ["run", *_]:
                base = self.pipeline_expression_candidates(prefix)
            case ["use", *_]:
                base = ["global", *self.registry.names()]
            case [name, *rest] if name in self.registry.plugins:
                base = self.plugin_candidates(name, prefix, rest)
            case ["load", *_]:
                base = self.load_candidates(prefix)
            case ["save", *_]:
                base = self.save_candidates(prefix)
            case ["vars", *_]:
                base = self.vars_candidates(prefix)
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
                return self.run_alias_candidates()
            case "pipeline":
                return self.pipeline_alias_candidates()
            case "job":
                return self.job_candidates()
            case "serial":
                return self.serial_candidates()
            case "key.any":
                return key_candidates()
            case "key.signing":
                return key_candidates(signing=True)
            case "key.verify":
                return key_candidates(verify=True)
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

    def completion_meta(self, candidate: str, line: str, prefix: str) -> str:
        """Return prompt-toolkit metadata for runtime entity completions."""
        if self.db is None:
            return ""
        kind, value = runtime_completion_target(candidate, line, prefix)
        match kind:
            case "job":
                try:
                    row = self.db.job(int(value))
                except ValueError:
                    return ""
                if row is None:
                    return ""
                artifacts = self.db.artifact_counts_by_job().get(str(row["id"]), 0)
                return f"serial={row['serial']} status={row['status']} artifacts={artifacts} command={row['command_line']}"
            case "run":
                serial = self.db.resolve_run_serial(value)
                artifacts = self.db.artifact_counts_by_run().get(serial, 0)
                for row in self.db.runs(active_only=False):
                    if row["command_run_id"] == serial:
                        return f"serial={serial} source={row['source']} artifacts={artifacts} events={row['events']}"
            case "pipeline":
                serial = self.db.resolve_pipeline_serial(value)
                artifacts = self.db.artifact_counts_by_pipeline().get(serial, 0)
                for row in self.db.pipelines(active_only=False):
                    if row["pipeline_id"] == serial:
                        return f"serial={serial} artifacts={artifacts} runs={row['runs']} events={row['events']}"
        return ""


class PromptToolkitCompleter(PromptToolkitCompleterBase):
    """Prompt-toolkit adapter around Bywaf's command-aware completer."""

    def __init__(self, completer: Completer):
        self.completer = completer

    def get_completions(self, document, complete_event: Any):
        """Yield prompt-toolkit Completion objects for the current buffer."""
        del complete_event
        if Completion is None:
            return
        line = document.text_before_cursor
        prefix = completion_prefix(line)
        candidates = self.completer.candidates(line)
        display_value_only = should_display_value_only(prefix, candidates)
        for candidate in candidates:
            yield Completion(
                self.completer.format_candidate(candidate),
                start_position=-len(prefix),
                display=display_label(candidate) if display_value_only else candidate,
                display_meta=self.completer.completion_meta(candidate, line, prefix),
            )


def prompt_toolkit_available() -> bool:
    """Return whether the richer prompt-toolkit REPL can be used."""
    return PromptSession is not None and KeyBindings is not None


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


def build_prompt_session(completer: Completer):
    """Create a prompt-toolkit session with Bywaf completion behavior."""
    if not prompt_toolkit_available():
        return None
    assert PromptSession is not None
    assert CompleteStyle is not None
    return PromptSession(
        completer=PromptToolkitCompleter(completer),
        complete_while_typing=False,
        complete_style=CompleteStyle.MULTI_COLUMN,
        reserve_space_for_menu=8,
        bottom_toolbar=lambda: completion_bottom_toolbar(completer),
        key_bindings=completion_key_bindings(completer),
    )


def completion_bottom_toolbar(completer: Completer):
    """Display completion menu help only while a menu is active."""
    if get_app is None or HTML is None:
        return ""
    try:
        if get_app().current_buffer.complete_state:
            select_key = completion_select_key_display(completer)
            wasd_hint = " | WASD navigates" if completion_wasd_selection_enabled(completer) else ""
            return HTML(
                f"<b>Completion:</b> <b>{select_key}</b> enters selection | "
                f"arrows move | <b>Enter</b> selects | <b>Esc</b> cancels{wasd_hint}"
            )
    except RuntimeError:
        return ""
    return ""


def completion_key_bindings(completer: Completer):
    """Return prompt-toolkit keybindings for completion selection."""
    if KeyBindings is None or has_completions is None:
        return None
    bindings = KeyBindings()
    select_key = completion_select_key(completer)

    try:
        register_select_completion_binding(bindings, select_key)
    except ValueError:
        register_select_completion_binding(bindings, DEFAULT_COMPLETION_SELECT_KEY)
    if completion_wasd_selection_enabled(completer):
        register_wasd_completion_bindings(bindings)

    return bindings


def register_select_completion_binding(bindings, select_key: str) -> None:
    """Register the configured completion-selection-mode key."""

    @bindings.add(select_key)
    def _select_completion(event) -> None:
        enter_completion_selection_mode(event)

    @bindings.add("enter", filter=has_completions)
    def _accept_completion(event) -> None:
        apply_current_completion(event)

    @bindings.add("escape", filter=has_completions)
    def _cancel_completion(event) -> None:
        event.current_buffer.cancel_completion()


def register_wasd_completion_bindings(bindings) -> None:
    """Register optional WASD completion-menu navigation keys."""

    @bindings.add("w", filter=has_completions)
    def _previous_completion(event) -> None:
        event.current_buffer.complete_previous()

    @bindings.add("a", filter=has_completions)
    def _left_completion(event) -> None:
        event.current_buffer.complete_previous()

    @bindings.add("s", filter=has_completions)
    def _next_completion(event) -> None:
        event.current_buffer.complete_next()

    @bindings.add("d", filter=has_completions)
    def _right_completion(event) -> None:
        event.current_buffer.complete_next()


def apply_current_completion(event) -> None:
    """Accept the highlighted completion, or the first completion if none selected."""
    buffer = event.app.layout.get_buffer_by_name(DEFAULT_BUFFER)
    if buffer is None or buffer.complete_state is None:
        return
    completion = buffer.complete_state.current_completion
    if completion is None and buffer.complete_state.completions:
        completion = buffer.complete_state.completions[0]
    if completion is not None:
        buffer.apply_completion(completion)


def enter_completion_selection_mode(event) -> None:
    """Open the completion menu and select the first item for navigation."""
    buffer = event.current_buffer
    if buffer.complete_state is None:
        buffer.start_completion(select_first=True)
        return
    if buffer.complete_state.current_completion is None and buffer.complete_state.completions:
        buffer.go_to_completion(0)


def completion_wasd_selection_enabled(completer: Completer) -> bool:
    """Return whether optional WASD completion navigation is enabled."""
    value = completer.registry.varstore.get(COMPLETION_WASD_SELECTION_VAR, "false")
    return framework_bool(value, default=False)


def completion_select_key(completer: Completer) -> str:
    """Return the configured prompt-toolkit key name for selection."""
    value = completer.registry.varstore.get(COMPLETION_SELECT_KEY_VAR, DEFAULT_COMPLETION_SELECT_KEY)
    key = str(value).strip()
    if key.casefold() in {"", "none", "off", "disabled"}:
        return DEFAULT_COMPLETION_SELECT_KEY
    return key


def framework_bool(value: str | None, *, default: bool) -> bool:
    """Parse a shell variable as a framework boolean."""
    if value is None:
        return default
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return default


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


def completion_select_key_display(completer: Completer) -> str:
    """Return a human-readable label for the configured selection key."""
    key = completion_select_key(completer)
    if key == "c-space":
        return "Ctrl-Space"
    if key.startswith("c-") and len(key) > 2:
        return f"Ctrl-{key[2:].upper()}"
    return key


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


def history_candidates(prefix: str) -> list[str]:
    """Complete timestamp-window selectors for the built-in history command."""
    selectors = ("since=", "until=")
    return [selector for selector in selectors if selector.startswith(prefix)]


def should_print_completion_menu(line: str, candidates: Sequence[str]) -> bool:
    """Use a custom menu for key=value completions so labels stay readable."""
    prefix = completion_prefix(line)
    return (
        len(candidates) > 1
        and "=" in prefix
        and should_display_value_only(prefix, candidates)
    )


def should_display_value_only(prefix: str, candidates: Sequence[str]) -> bool:
    """Return whether completion display should hide a repeated key= prefix."""
    return "=" in prefix and all(candidate.startswith(prefix.split("=", 1)[0] + "=") for candidate in candidates)


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
