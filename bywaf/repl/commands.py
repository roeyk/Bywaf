"""Built-in REPL command handlers and mutable shell commands.

Provides the dispatch table and handlers for built-ins such as help, history,
set, use, run, event, plugin, config, script, prompt, jobs, steps, and project.

Used by:
- bywaf.repl.shell: dispatches parsed REPL lines to these handlers.
- tests: patch command-owned dependencies such as secret key loading."""


from __future__ import annotations

import getpass
import shlex
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..command.parser import expand_variables_in_text
from ..event_filters import event_matches_payload_filters, parse_event_sort, select_event_rows
from ..framework_requests import process_framework_requests
from .display import (
    format_var_assignment,
    print_commandlets,
    print_event_info,
    print_events,
    print_help,
    print_history,
    print_info,
    print_job,
    print_plugins,
    print_run_variables,
    print_topics,
    print_triggers,
)
from .display import display_expansion_preview
from .persistence import load_config, load_history, save_config, save_history
from .preferences import (
    THEME_KEY,
    apply_preferences,
    format_preference_assignment,
    load_preferences,
    preference_snapshot,
    resolve_preferences_path,
    save_preferences,
    set_preference,
    unset_preference,
)
from .resources import (
    DEFAULT_CONFIG,
    DEFAULT_HISTORY,
    DEFAULT_SCRIPT_DIR,
    dispatch_project_command,
    load_plugin_resource,
    print_project_info,
    parse_resource_assignment,
    resolve_resource_path,
    run_script,
)
from .themes import apply_theme_file, apply_theme_name, theme_names
from ..runner import Runner
from ..secret.store import load_or_create_fingerprint_key
from ..secret.input import SECRET_BLOCK_VALUE
from ..command.names import PROJECT_ALIAS_COMMAND, SET_COMMAND, SETG_COMMAND

if TYPE_CHECKING:
    from .shell import ShellState


ReplCommandHandler = Callable[[Runner, Any, str | None, str], str | None]
EVENT_SELECTOR_KEYS = {"job", "step", "pipeline", "serial", "topic"}
SUPPRESSED_COMMANDLET_OUTPUT_TOPICS = {"framework.file.page.requested", "report.rendered"}


def handle_exit_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Exit the REPL."""
    del runner, state, rest, line
    return "exit"


def handle_help_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print general or command-specific help."""
    del state, line
    print_help(runner, rest)
    return None


def handle_plugins_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print loaded plugin providers."""
    del state, rest, line
    print_plugins(runner)
    return None


def handle_cmds_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print commandlets, optionally through the pager."""
    del state, line
    print_commandlets(runner, page=rest == "--page")
    return None


def handle_triggers_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print trigger rules."""
    del state, rest, line
    print_triggers(runner)
    return None


def handle_history_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print command history."""
    del line
    if rest and history_resource_command(runner, state, shlex.split(rest)):
        return None
    selectors = parse_history_selectors(shlex.split(rest)) if rest else None
    print_history(state.session_history, selectors, runner)
    return None


def history_resource_command(runner: Runner, state: ShellState, tokens: list[str]) -> bool:
    """Handle `history load/save` forms; return whether an action ran."""
    action = tokens[0] if tokens else ""
    if action not in {"load", "save"}:
        return False
    file_value = selector_value(tokens[1:], "file")
    path = resolve_resource_path(file_value or "", Path("."), DEFAULT_HISTORY)
    if action == "load":
        del runner
        load_history(state, path)
    else:
        save_history(state, path, encrypt="--encrypt" in tokens[1:])
    return True


def handle_config_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load or save framework configuration."""
    del state, line
    tokens = shlex.split(rest) if rest else []
    if not tokens:
        print("usage: config load file=<path>, config save file=<path> [--encrypt], config theme name=<preset>, or config theme file=<path>")
        return None
    action = tokens[0]
    if action == "theme":
        apply_theme_command(runner, tokens[1:])
        return None
    file_value = selector_value(tokens[1:], "file")
    path = resolve_resource_path(file_value or "", Path("."), DEFAULT_CONFIG)
    if action == "load":
        load_config(runner, path)
    elif action == "save":
        save_config(runner, path, encrypt="--encrypt" in tokens[1:])
    else:
        print("usage: config load file=<path>, config save file=<path> [--encrypt], config theme name=<preset>, or config theme file=<path>")
    return None


def apply_theme_command(runner: Runner, tokens: list[str]) -> None:
    """Apply a named or file-backed syntax/display theme."""
    if not tokens:
        print("themes: " + ", ".join(theme_names()))
        return
    name = selector_value(tokens, "name")
    file_value = selector_value(tokens, "file")
    if bool(name) == bool(file_value):
        raise ValueError("usage: config theme name=<preset> or config theme file=<path>")
    if name:
        apply_theme_name(runner, name)
        print(f"loaded theme={name}")
        return
    assert file_value is not None
    path = resolve_resource_path(file_value, Path("."))
    apply_theme_file(runner, path)
    print(f"loaded theme={path}")


def handle_pref_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Manage user-local preferences that should follow the operator."""
    del line
    tokens = shlex.split(rest) if rest else []
    action = tokens[0] if tokens else "list"
    args = tokens[1:] if tokens else []
    file_value = selector_value(tokens, "file")
    path = resolve_preferences_path(file_value)
    theme_value = selector_value(tokens, "theme")
    if theme_value:
        set_preference(runner, state, path, THEME_KEY, theme_value)
        print(f"saved pref theme={theme_value}")
    elif action == "theme":
        print("themes: " + ", ".join(theme_names()))
    elif action == "list":
        print_preferences(runner, state, path)
    elif action == "load":
        values = load_preferences(path)
        apply_preferences(runner, state, values)
        print(f"loaded pref={path}")
    elif action == "save":
        values = preference_snapshot(runner, state, load_preferences(path))
        save_preferences(path, values)
        print(f"saved pref={path}")
    elif action == "set":
        key, value = preference_assignment(args)
        set_preference(runner, state, path, key, value)
        print(f"saved pref {key}={value}")
    elif action == "unset":
        key = preference_key_argument(args)
        removed = unset_preference(runner, state, path, key)
        print(f"unset pref {key}" if removed else f"pref not set: {key}")
    elif action == "prompt":
        pattern = preference_prompt_pattern(args)
        set_preference(runner, state, path, "prompt.pattern", pattern)
        print(f"saved pref prompt={pattern}")
    else:
        print("usage: pref [list|load|save] [file=<path>], pref set key=value [file=<path>], pref unset key [file=<path>], pref theme=<preset> [file=<path>], or pref prompt <pattern> [file=<path>]")
    return None


def print_preferences(runner: Runner, state: ShellState, path: Path) -> None:
    """Print persisted preferences, or active preference-like values."""
    values = load_preferences(path)
    if not values:
        values = preference_snapshot(runner, state, {})
    for key, value in sorted(values.items()):
        print(format_preference_assignment(key, value))


def preference_assignment(tokens: Sequence[str]) -> tuple[str, str]:
    """Return the first non-file `key=value` preference assignment."""
    for token in tokens:
        if token.startswith("file="):
            continue
        if "=" not in token:
            continue
        return token.split("=", 1)
    raise ValueError("usage: pref set key=value [file=<path>]")


def preference_key_argument(tokens: Sequence[str]) -> str:
    """Return the first non-selector token as a preference key."""
    for token in tokens:
        if token.startswith("file="):
            continue
        if token:
            return token
    raise ValueError("usage: pref unset key [file=<path>]")


def preference_prompt_pattern(tokens: Sequence[str]) -> str:
    """Return prompt pattern text from `pref prompt` args."""
    pattern_tokens = [token for token in tokens if not token.startswith("file=")]
    pattern = " ".join(pattern_tokens)
    if not pattern:
        raise ValueError("usage: pref prompt <pattern> [file=<path>]")
    return pattern


def handle_script_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load/run or save REPL scripts."""
    del line
    tokens = shlex.split(rest) if rest else []
    if not tokens:
        print("usage: script load file=<path>, script save file=<path> [--encrypt]")
        return None
    action = tokens[0]
    file_value = selector_value(tokens[1:], "file")
    if action == "load":
        if not file_value:
            raise ValueError("usage: script load file=<path>")
        run_script(runner, resolve_script_load_path(file_value), state)
    elif action == "save":
        path = resolve_resource_path(file_value or "", Path("."), DEFAULT_HISTORY)
        save_history(state, path, encrypt="--encrypt" in tokens[1:])
    else:
        print("usage: script load file=<path>, script save file=<path> [--encrypt]")
    return None


def handle_info_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print runtime overview."""
    del state, rest, line
    print_info(runner)
    return None


def handle_use_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the active variable context."""
    del line
    if rest is None:
        print(state.active_context or "global")
    else:
        set_active_context(runner, state, rest)
    return None


def handle_vars_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """List, show, or set variables."""
    del line
    if rest is None:
        print_vars(runner, state)
    elif "=" in rest:
        set_var(runner, state, rest)
    else:
        print_var(runner, state, rest)
    return None


def handle_setg_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Set or show one explicitly global variable."""
    del line
    if rest is None:
        print("usage: setg [--secret] name=value")
    elif "=" in rest:
        set_var(runner, state, globalize_setg(rest), source=SETG_COMMAND)
    else:
        print_var(runner, state, f"global.{rest.strip()}")
    return None


def handle_topics_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print event topics."""
    del state, line
    print_topics(runner, rest or "")
    return None


def handle_project_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or dispatch project commands."""
    del line
    if rest is None:
        print_project_info(runner)
    else:
        dispatch_project_command(runner, state, shlex.split(rest))
    return None


def handle_event_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print matching events."""
    del line
    if rest is None:
        print("usage: event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...]")
        return None
    rest = expand_builtin_filter_text(runner, state, rest, "event")
    tokens = shlex.split(rest)
    selector, filters, limit, sort_key = parse_event_query(tokens)
    if selector.isdigit():
        print_filtered_event_id(runner, selector, filters)
    elif selector.startswith("job=") and not filters:
        print_job(runner, str(resolve_job_selector(runner, selector.split("=", 1)[1])))
    elif selector.startswith("job="):
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_for_job(resolve_job_selector(runner, selector.split("=", 1)[1]), limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("step="):
        run_id = runner.runtime.resolve_run_serial(selector.split("=", 1)[1])
        print_run_variables(runner, run_id)
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(command_run_id=run_id, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("pipeline="):
        pipeline_id = runner.runtime.resolve_pipeline_serial(selector.split("=", 1)[1])
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(pipeline_id=pipeline_id, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("serial="):
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_for_serial(selector.split("=", 1)[1], limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    elif selector.startswith("topic="):
        topic = selector.split("=", 1)[1]
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(topic=topic, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    else:
        source_limit = event_source_limit(limit, filters)
        events = runner.events.events_matching(topic=selector or None, limit=source_limit)
        print_events(select_event_rows(events, filters, sort_key, limit), runner)
    return None


def print_filtered_event_id(runner: Runner, selector: str, filters: dict[str, str]) -> None:
    """Print a single event id, optionally only when it matches payload filters."""
    if not filters:
        print_event_info(runner, selector)
        return
    event = runner.events.event_by_id(int(selector))
    if event and event_matches_payload_filters(event, filters):
        print_events([event], runner)


def parse_event_query(tokens: Sequence[str]) -> tuple[str, dict[str, str], int, str]:
    """Split `event` input into one scope selector, payload filters, and limit.

    The first non-filter token remains the traditional topic/id selector.
    Additional `key=value` tokens filter event payloads, so operators can write
    `event port.open host=192.0.2.10` without learning a separate query syntax.
    """
    selector = ""
    filters: dict[str, str] = {}
    limit = 100
    sort_key = "time"
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator:
            if not key or not value:
                raise ValueError("event filters must be key=value")
            if key == "limit":
                limit = parse_event_limit(value)
            elif key == "sort":
                sort_key = parse_event_sort(value)
            elif key in EVENT_SELECTOR_KEYS and not selector:
                selector = token
            elif key in EVENT_SELECTOR_KEYS:
                raise ValueError("event accepts only one scope selector")
            else:
                filters[key] = value
            continue
        if selector:
            raise ValueError("usage: event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...]")
        selector = token
    return selector, filters, limit, sort_key


def parse_event_limit(raw: str) -> int:
    """Parse the maximum number of event rows to display."""
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid event limit= value: {raw}") from exc
    if limit < 1:
        raise ValueError("event limit= must be at least 1")
    return limit


def event_source_limit(display_limit: int, filters: dict[str, str]) -> int:
    """Fetch extra source rows when filtering so older matches are not hidden."""
    if not filters:
        return display_limit
    return max(1000, display_limit * 20)


def expand_builtin_filter_text(runner: Runner, state: ShellState, text: str | None, command: str) -> str | None:
    """Expand `$vars` in built-in query/filter text.

    Commandlet execution already expands variables in the runner parser. REPL
    built-ins such as `event`, `jobs`, `pipelines`, and `steps` parse their own
    filter syntax, so they need the same operator convenience before
    tokenization.
    """
    if text is None:
        display_expansion_preview(runner, command, changed=False)
        return None
    if "$" not in text:
        display_expansion_preview(runner, f"{command} {text}".strip(), changed=False)
        return text
    scope = state.active_context or command
    expanded, _names = expand_variables_in_text(text, runner.registry.varstore, scope)
    display_expansion_preview(runner, f"{command} {expanded}".strip(), changed=expanded != text)
    return expanded


def handle_events_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print recent events."""
    del state, line
    limit = parse_events_selectors(shlex.split(rest)) if rest else 25
    print_events(runner.events.recent_events(limit), runner)
    return None


def handle_run_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Execute the active commandlet context."""
    del line
    if rest is not None:
        print("usage: run")
        return None
    if not state.active_context:
        print("no active commandlet; use <commandlet> first")
        return None
    # `run` is a convenience for the active `use` context. It does not create a
    # new command syntax path; direct commandlet invocation remains primary.
    execute_repl_commandlet(runner, state, state.active_context)
    return None


def handle_prompt_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the prompt pattern."""
    del line
    if rest is None:
        print(state.prompt_pattern)
    else:
        set_prompt_pattern(runner, state, rest, source="user")
    return None


def handle_plugin_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load filesystem plugins."""
    del line
    if rest is None:
        print("usage: plugin load=<path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    plugin_value = ""
    catalog_path: str | None = None
    use_target: str | None = None
    for token in tokens:
        # `plugin load=` is the explicit form. path= optionally remaps the local
        # filesystem plugin into a catalog path for development/testing.
        key, value = parse_resource_assignment(token)
        if key == "load":
            plugin_value = value
        elif key == "path":
            catalog_path = value
        elif key == "--use":
            use_target = value or ""
        elif token == "--use":
            use_target = ""
    if not plugin_value:
        print("usage: plugin load=<path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, plugin_value, forced, catalog_path=catalog_path)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def handle_pload_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Short alias for loading filesystem plugins."""
    del line
    if rest is None:
        print("usage: pload <path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    catalog_path: str | None = None
    use_target: str | None = None
    paths: list[str] = []
    for token in tokens:
        # pload keeps the common path short: the sole positional token is the
        # plugin path, while path=/--use/--force retain the same meanings.
        key, value = parse_resource_assignment(token)
        if token == "--force":
            continue
        if token == "--use":
            use_target = ""
            continue
        if key == "--use":
            use_target = value or ""
            continue
        if key == "path":
            catalog_path = value
            continue
        paths.append(token)
    if len(paths) != 1:
        print("usage: pload <path> [path=<catalog/path>] [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, paths[0], forced, catalog_path=catalog_path)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def handle_exec_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Execute an operating-system command."""
    del state, line
    if rest is None:
        print_help(runner, "exec")
    else:
        execute_shell_command(runner, rest)
    return None


def execute_repl_commandlet(runner: Runner, state: ShellState, command: str) -> None:
    """Run a commandlet line and print emitted events."""
    events = runner.execute(command)
    process_framework_requests(runner, state)
    # Some commandlets emit audit events after also requesting formatted console
    # output. Keep those events in storage, but avoid echoing raw payloads in
    # the REPL after the operator-facing renderer has already printed.
    print_events(visible_commandlet_events(events), runner)


def visible_commandlet_events(events):
    """Return commandlet events that should be echoed after execution."""
    return [event for event in events if event.topic not in SUPPRESSED_COMMANDLET_OUTPUT_TOPICS]


def resolve_job_selector(runner: Runner, value: str) -> int:
    """Resolve a local job id or durable job serial for built-in selectors."""
    try:
        return int(value)
    except ValueError:
        resolved = runner.runtime.job_id_for_serial(value)
        if resolved is None:
            raise ValueError(f"unknown job: {value}") from None
        return int(resolved)


def execute_shell_command(runner: Runner, command: str) -> int:
    """Run an OS command argv and audit its lifecycle."""
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if not argv:
        print_help(runner, "exec")
        return 2
    # Shell execution is intentionally explicit through `exec`; normal commandlet
    # execution remains the default REPL behavior.
    started = runner.events.publish(
        "shell.exec.started",
        {"command": command, "argv": argv},
        "framework",
    )
    completed = subprocess.run(argv, check=False)
    topic = "shell.exec.completed" if completed.returncode == 0 else "shell.exec.failed"
    runner.events.publish(
        topic,
        {
            "command": command,
            "argv": argv,
            "returncode": completed.returncode,
            "ok": completed.returncode == 0,
            "request_event_id": started.id,
        },
        "framework",
    )
    return completed.returncode


REPL_COMMAND_HANDLERS: dict[str, ReplCommandHandler] = {
    "?": handle_help_command,
    "cmds": handle_cmds_command,
    "config": handle_config_command,
    "event": handle_event_command,
    "events": handle_events_command,
    "exec": handle_exec_command,
    "exit": handle_exit_command,
    "help": handle_help_command,
    "history": handle_history_command,
    "info": handle_info_command,
    "plugin": handle_plugin_command,
    "plugins": handle_plugins_command,
    "pload": handle_pload_command,
    "pref": handle_pref_command,
    "project": handle_project_command,
    PROJECT_ALIAS_COMMAND: handle_project_command,
    "prompt": handle_prompt_command,
    "q": handle_exit_command,
    "quit": handle_exit_command,
    "run": handle_run_command,
    "script": handle_script_command,
    "topics": handle_topics_command,
    "triggers": handle_triggers_command,
    "use": handle_use_command,
    SET_COMMAND: handle_vars_command,
    SETG_COMMAND: handle_setg_command,
}


def set_prompt_pattern(runner: Runner, state: ShellState, pattern: str, *, source: str) -> None:
    """Set the REPL prompt and record the change as an auditable event."""
    old_prompt = state.prompt_pattern
    state.prompt_pattern = pattern
    runner.events.publish(
        "shell.prompt.updated",
        {"old_prompt": old_prompt, "new_prompt": pattern, "source": source},
        "framework",
    )


def parse_events_selectors(selectors: Sequence[str]) -> int:
    """Parse `events [tail|--tail] [last=N]` and return the requested tail size."""
    limit = 25
    seen_last = False
    for selector in selectors:
        if selector in {"tail", "--tail"}:
            continue
        if selector.startswith("last="):
            if seen_last:
                raise ValueError("events last= may only be provided once")
            seen_last = True
            limit = parse_events_last_value(selector.split("=", 1)[1])
            continue
        raise ValueError("usage: events [tail|--tail] [last=N]")
    return limit


def parse_events_last_value(raw: str) -> int:
    """Parse a positive integer event tail size."""
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid events last= value: {raw}") from exc
    if limit < 1:
        raise ValueError("events last= must be at least 1")
    return limit


def selector_value(tokens: Sequence[str], key: str) -> str | None:
    """Return selector value from `key=value` tokens."""
    prefix = f"{key}="
    for token in tokens:
        if token.startswith(prefix):
            return token.split("=", 1)[1]
    return None


def resolve_script_load_path(file_value: str) -> Path:
    """Resolve script loads from cwd first, then the project script directory."""
    direct = Path(file_value).expanduser()
    if direct.exists():
        return direct
    return resolve_resource_path(file_value, DEFAULT_SCRIPT_DIR)


def parse_history_selectors(tokens: Sequence[str]) -> dict[str, str]:
    """Parse `history since=... until=...` selector tokens."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        key, value = token.split("=", 1)
        if key not in {"since", "until"}:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        if not value:
            raise ValueError(f"history {key}= requires a value")
        selectors[key] = value
    return selectors


def print_vars(runner: Runner, state: ShellState) -> None:
    """Print session variables in stable key order."""
    del state
    for key, value in runner.registry.varstore.items():
        print(format_var_assignment(runner, key, value))


def print_var(runner: Runner, state: ShellState, name: str) -> None:
    """Print one session variable after applying active-context scoping."""
    key = resolve_var_key(runner, state, name.strip())
    value = runner.registry.varstore.get(key)
    if value is None:
        print(f"error: variable not set: {key}")
        return
    print(format_var_assignment(runner, key, value))


def set_var(runner: Runner, state: ShellState, assignment: str, *, source: str = SET_COMMAND) -> None:
    """Set a REPL variable, keeping explicitly secret values out of varstore."""
    assignment, explicit_secret = parse_var_assignment_flags(assignment)
    key, value = assignment.split("=", 1)
    resolved_key = resolve_var_key(runner, state, key.strip())
    cleaned_value = clean_var_value(value)
    if explicit_secret:
        # Secrets store a fingerprinted reference in varstore and the cleartext
        # in the DB secret table. This keeps command rendering/audit output from
        # exposing the original value.
        hidden_values = getattr(state, "secret_values", {})
        hidden_value = hidden_values.get(resolved_key) or hidden_values.get(key.strip())
        if cleaned_value == SECRET_BLOCK_VALUE and hidden_value is not None:
            cleaned_value = hidden_value
        elif cleaned_value == "":
            cleaned_value = read_secret_value(resolved_key)
        secret_ref = runner.registry.secrets.put(
            resolved_key,
            cleaned_value,
            key=load_or_create_fingerprint_key(),
            source=source,
        )
        runner.registry.varstore.set(resolved_key, secret_ref.ref)
        runner.db.store_secret(secret_ref, cleaned_value)
        if not runner.db.encrypted:
            print(f"warning: storing secret variable {resolved_key} in plaintext database {runner.db.path}")
        print(format_var_assignment(runner, resolved_key, secret_ref.ref))
        warn_if_pending_catalog_variable(runner, resolved_key)
        return
    runner.registry.varstore.set(resolved_key, cleaned_value)
    warn_if_pending_catalog_variable(runner, resolved_key)


def read_secret_value(name: str) -> str:
    """Read one secret value without echoing it to the terminal."""
    return getpass.getpass(f"Secret for {name}: ")


def clean_var_value(value: str) -> str:
    """Normalize one `set name=value` value while honoring shell quotes."""
    stripped = value.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    if len(tokens) == 1:
        return tokens[0]
    return stripped


def parse_var_assignment_flags(assignment: str) -> tuple[str, bool]:
    """Return assignment text and whether it requested explicit secret storage."""
    stripped = assignment.strip()
    left, separator, right = stripped.partition("=")
    if separator:
        left_tokens = shlex.split(left)
        if "--secret" in left_tokens:
            key_tokens = [token for token in left_tokens if token != "--secret"]
            if len(key_tokens) != 1:
                raise ValueError(f"usage: {SET_COMMAND} [--secret] name=value")
            return f"{key_tokens[0]}={right}", True
    if stripped.endswith(" --secret"):
        return stripped.removesuffix(" --secret").strip(), True
    return assignment, False


def globalize_setg(assignment: str) -> str:
    """Convert `setg name=value` text to a `global.name=value` assignment."""
    stripped = assignment.strip()
    if stripped.startswith("--secret "):
        prefix = "--secret "
        return f"{prefix}global.{stripped.removeprefix(prefix).strip()}"
    if " --secret" in stripped:
        key_value = stripped.removesuffix(" --secret").strip()
        return f"global.{key_value} --secret"
    return f"global.{stripped}"


def warn_if_pending_catalog_variable(runner: Runner, key: str) -> None:
    """Warn when storing a commandlet-scoped variable before that commandlet is loaded."""
    if "/" not in key or "." not in key:
        return
    if key.startswith("display/"):
        return
    scope, variable = key.rsplit(".", 1)
    if not scope or not variable or runner.registry.has_commandlet(scope):
        return
    print(f"warning: {scope} is not loaded; storing {key} until that commandlet is loaded")


def set_active_context(runner: Runner, state: ShellState, target: str) -> None:
    """Set the active commandlet context for short variable assignments."""
    if target == "global":
        state.active_context = None
        if state.completer is not None:
            state.completer.active_context = None
        print("using global")
        return
    if not runner.registry.has_commandlet(target):
        # A provider may expose a default commandlet. If it exposes multiple and
        # none is marked default, require the user to choose explicitly.
        default = runner.registry.provider_default(target)
        if default is None:
            commandlets = runner.registry.provider_commandlet_names(target)
            if commandlets:
                choices = ", ".join(commandlets)
                raise ValueError(f"{target} exposes multiple commandlets; choose one: {choices}")
            raise ValueError(f"unknown commandlet context: {target}")
        target = default
    commandlet = runner.registry.variable_scope(target)
    state.active_context = commandlet
    if state.completer is not None:
        state.completer.active_context = commandlet
    print(f"using {commandlet}")


def maybe_use_loaded_commandlet(
    runner: Runner,
    state: ShellState,
    commandlets: Sequence[str],
    target: str | None,
) -> None:
    """Optionally switch active context after loading a plugin provider."""
    if target is None:
        # Loading does not implicitly change `use`; print the likely next step
        # while avoiding surprises for providers with multiple commandlets.
        if commandlets:
            print(f"try: use {commandlets[0]}")
        return
    if target:
        set_active_context(runner, state, target)
        return
    if len(commandlets) == 1:
        set_active_context(runner, state, commandlets[0])
        return
    if not commandlets:
        print("loaded plugin exposes no commandlets")
        return
    print("loaded plugin exposes multiple commandlets; choose one:")
    for commandlet in commandlets:
        print(f"  use {commandlet}")
    print("or reload with --use=<commandlet>")


def resolve_var_key(runner: Runner, state: ShellState, key: str) -> str:
    """Resolve unqualified variable keys through the active `use` context."""
    if key.startswith("global."):
        return key
    if key.startswith("display/"):
        return key
    if "/" in key and "." in key:
        # Fully-qualified commandlet variables use catalog/path.command_var.
        # Preserve unloaded catalog variables so they can apply after loading.
        scope, name = key.rsplit(".", 1)
        if runner.registry.has_commandlet(scope):
            return f"{runner.registry.variable_scope(scope)}.{name}"
        return key
    if "." in key:
        scope, name = key.rsplit(".", 1)
        if runner.registry.has_commandlet(scope):
            return f"{runner.registry.variable_scope(scope)}.{name}"
    if state.active_context:
        # In a `use` context, bare `set timeout=5` means
        # set <active-commandlet>.timeout=5.
        return f"{state.active_context}.{key}"
    return key
