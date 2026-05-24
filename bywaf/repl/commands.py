"""Built-in REPL command handlers and mutable shell commands.

Provides the dispatch table and handlers for built-ins such as help, history,
set, use, go, event, plugin, config, script, prompt, jobs, steps, and project.

Used by:
- bywaf.repl.shell: dispatches parsed REPL lines to these handlers.
- tests: patch command-owned dependencies such as secret key loading."""


from __future__ import annotations

import shlex
import getpass
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
    print_runs,
    print_topics,
    print_triggers,
)
from .persistence import load_config, load_history, save_config, save_history
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
from ..runner import Runner
from ..secrets import load_or_create_fingerprint_key
from ..secret_input import SECRET_BLOCK_VALUE
from ..command_names import PROJECT_ALIAS_COMMAND, SET_COMMAND

if TYPE_CHECKING:
    from .shell import ShellState


ReplCommandHandler = Callable[[Runner, Any, str | None, str], str | None]


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
        print("usage: config load file=<path>, config save file=<path> [--encrypt]")
        return None
    action = tokens[0]
    file_value = selector_value(tokens[1:], "file")
    path = resolve_resource_path(file_value or "", Path("."), DEFAULT_CONFIG)
    if action == "load":
        load_config(runner, path)
    elif action == "save":
        save_config(runner, path, encrypt="--encrypt" in tokens[1:])
    else:
        print("usage: config load file=<path>, config save file=<path> [--encrypt]")
    return None


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
        run_script(runner, resolve_resource_path(file_value, DEFAULT_SCRIPT_DIR), state)
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


def handle_jobs_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run the job-list commandlet shortcut."""
    del line
    suffix = f" {rest}" if rest in {"--all", "--page"} else ""
    events = runner.execute(f"job list{suffix}")
    process_framework_requests(runner, state)
    print_events(events, runner)
    return None


def handle_pipelines_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run the pipeline-list commandlet shortcut."""
    del line
    suffix = " --page" if rest == "--page" else ""
    events = runner.execute(f"pipeline list{suffix}")
    process_framework_requests(runner, state)
    print_events(events, runner)
    return None


def handle_steps_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print commandlet execution steps."""
    del state, line
    print_runs(runner, active_only=rest != "--all")
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
    del state, line
    if rest is None:
        print("usage: event <id|topic|job=id|run=id|pipeline=id|serial=id>")
    elif rest.isdigit():
        print_event_info(runner, rest)
    elif rest.startswith("job="):
        print_job(runner, rest.split("=", 1)[1])
    elif rest.startswith("run="):
        run_id = runner.runtime.resolve_run_serial(rest.split("=", 1)[1])
        print_run_variables(runner, run_id)
        print_events(runner.events.events_matching(command_run_id=run_id), runner)
    elif rest.startswith("pipeline="):
        pipeline_id = runner.runtime.resolve_pipeline_serial(rest.split("=", 1)[1])
        print_events(runner.events.events_matching(pipeline_id=pipeline_id), runner)
    elif rest.startswith("serial="):
        print_events(runner.events.events_for_serial(rest.split("=", 1)[1]), runner)
    elif rest.startswith("topic="):
        print_events(runner.events.events_matching(topic=rest.split("=", 1)[1]), runner)
    else:
        print_events(runner.events.events_for_topic(rest), runner)
    return None


def handle_events_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print recent events."""
    del state, line
    limit = parse_events_selectors(shlex.split(rest)) if rest else 25
    print_events(runner.events.recent_events(limit), runner)
    return None


def handle_go_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Execute the active commandlet context."""
    del line
    if rest is not None:
        print("usage: go")
        return None
    if not state.active_context:
        print("no active commandlet; use <commandlet> first")
        return None
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
        print("usage: plugin load=<path> [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    plugin_value = ""
    use_target: str | None = None
    for token in tokens:
        key, value = parse_resource_assignment(token)
        if key == "load":
            plugin_value = value
        elif key == "--use":
            use_target = value or ""
        elif token == "--use":
            use_target = ""
    if not plugin_value:
        print("usage: plugin load=<path> [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, plugin_value, forced)
    maybe_use_loaded_commandlet(runner, state, commandlets, use_target)
    return None


def handle_pload_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Short alias for loading filesystem plugins."""
    del line
    if rest is None:
        print("usage: pload <path> [--force] [--use[=<commandlet>]]")
        return None
    tokens = shlex.split(rest)
    forced = "--force" in tokens
    use_target: str | None = None
    paths: list[str] = []
    for token in tokens:
        key, value = parse_resource_assignment(token)
        if token == "--force":
            continue
        if token == "--use":
            use_target = ""
            continue
        if key == "--use":
            use_target = value or ""
            continue
        paths.append(token)
    if len(paths) != 1:
        print("usage: pload <path> [--force] [--use[=<commandlet>]]")
        return None
    commandlets = load_plugin_resource(runner, state, paths[0], forced)
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


def handle_step_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Inspect one commandlet execution step."""
    del state, line
    if rest is None:
        print_help(runner, "step")
        return None
    run_id = runner.runtime.resolve_run_serial(rest)
    print_run_variables(runner, run_id)
    print_events(runner.events.events_matching(command_run_id=run_id), runner)
    return None


def execute_repl_commandlet(runner: Runner, state: ShellState, command: str) -> None:
    """Run a commandlet line and print emitted events."""
    events = runner.execute(command)
    process_framework_requests(runner, state)
    print_events(events, runner)


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
    "go": handle_go_command,
    "event": handle_event_command,
    "events": handle_events_command,
    "exec": handle_exec_command,
    "exit": handle_exit_command,
    "help": handle_help_command,
    "history": handle_history_command,
    "info": handle_info_command,
    "jobs": handle_jobs_command,
    "pipelines": handle_pipelines_command,
    "plugin": handle_plugin_command,
    "plugins": handle_plugins_command,
    "pload": handle_pload_command,
    "project": handle_project_command,
    PROJECT_ALIAS_COMMAND: handle_project_command,
    "prompt": handle_prompt_command,
    "q": handle_exit_command,
    "quit": handle_exit_command,
    "script": handle_script_command,
    "step": handle_step_command,
    "steps": handle_steps_command,
    "topics": handle_topics_command,
    "triggers": handle_triggers_command,
    "use": handle_use_command,
    SET_COMMAND: handle_vars_command,
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
    key = resolve_var_key(state, name.strip())
    value = runner.registry.varstore.get(key)
    if value is None:
        print(f"error: variable not set: {key}")
        return
    print(format_var_assignment(runner, key, value))


def set_var(runner: Runner, state: ShellState, assignment: str) -> None:
    """Set a REPL variable, keeping explicitly secret values out of varstore."""
    assignment, explicit_secret = parse_var_assignment_flags(assignment)
    key, value = assignment.split("=", 1)
    resolved_key = resolve_var_key(state, key.strip())
    cleaned_value = value.strip()
    if explicit_secret:
        hidden_value = getattr(state, "secret_values", {}).get(resolved_key)
        if cleaned_value == SECRET_BLOCK_VALUE and hidden_value is not None:
            cleaned_value = hidden_value
        elif cleaned_value == "":
            cleaned_value = read_secret_value(resolved_key)
        secret_ref = runner.registry.secrets.put(
            resolved_key,
            cleaned_value,
            key=load_or_create_fingerprint_key(),
            source=SET_COMMAND,
        )
        runner.registry.varstore.set(resolved_key, secret_ref.ref)
        runner.db.store_secret(secret_ref, cleaned_value)
        if not runner.db.encrypted:
            print(f"warning: storing secret variable {resolved_key} in plaintext database {runner.db.path}")
        print(format_var_assignment(runner, resolved_key, secret_ref.ref))
        return
    runner.registry.varstore.set(resolved_key, cleaned_value)


def read_secret_value(name: str) -> str:
    """Read one secret value without echoing it to the terminal."""
    return getpass.getpass(f"Secret for {name}: ")


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


def set_active_context(runner: Runner, state: ShellState, target: str) -> None:
    """Set the active commandlet context for short variable assignments."""
    if target == "global":
        state.active_context = None
        if state.completer is not None:
            state.completer.active_context = None
        print("using global")
        return
    commandlet = target.split(".", 1)[-1]
    if commandlet not in runner.registry.plugins:
        raise ValueError(f"unknown commandlet context: {target}")
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


def resolve_var_key(state: ShellState, key: str) -> str:
    """Resolve unqualified variable keys through the active `use` context."""
    if "." in key or key.startswith("global."):
        return key
    if state.active_context:
        return f"{state.active_context}.{key}"
    return key
