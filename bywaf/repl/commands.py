"""Built-in REPL command handlers and mutable shell commands.

Provides the dispatch table and handlers for built-ins such as help, history,
var, use, event, load, save, prompt, jobs, runs, and project.

Used by:
- bywaf.repl.shell: dispatches parsed REPL lines to these handlers.
- tests: patch command-owned dependencies such as secret key loading."""


from __future__ import annotations

import shlex
import getpass
from collections.abc import Callable, Sequence
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
from .resources import dispatch_project_command, load_repl_resource, print_project_info, save_repl_resource
from ..runner import Runner
from ..secrets import load_or_create_fingerprint_key
from ..secret_input import SECRET_BLOCK_VALUE

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
    selectors = parse_history_selectors(shlex.split(rest)) if rest else None
    print_history(state.session_history, selectors, runner)
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


def handle_runs_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print commandlet runs."""
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


def handle_prompt_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the prompt pattern."""
    del line
    if rest is None:
        print(state.prompt_pattern)
    else:
        set_prompt_pattern(runner, state, rest, source="user")
    return None


def handle_load_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load a REPL resource."""
    del line
    if rest is not None:
        load_repl_resource(runner, rest, state)
    return None


def handle_save_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Save a REPL resource."""
    del line
    if rest is None:
        print("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
    else:
        save_repl_resource(runner, rest, state)
    return None


def handle_run_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run a commandlet pipeline."""
    del line
    if rest is not None:
        execute_repl_commandlet(runner, state, rest)
    return None


def execute_repl_commandlet(runner: Runner, state: ShellState, command: str) -> None:
    """Run a commandlet line and print emitted events."""
    events = runner.execute(command)
    process_framework_requests(runner, state)
    print_events(events, runner)


REPL_COMMAND_HANDLERS: dict[str, ReplCommandHandler] = {
    "?": handle_help_command,
    "cmds": handle_cmds_command,
    "event": handle_event_command,
    "events": handle_events_command,
    "exit": handle_exit_command,
    "help": handle_help_command,
    "history": handle_history_command,
    "info": handle_info_command,
    "jobs": handle_jobs_command,
    "load": handle_load_command,
    "pipelines": handle_pipelines_command,
    "plugins": handle_plugins_command,
    "project": handle_project_command,
    "prompt": handle_prompt_command,
    "q": handle_exit_command,
    "quit": handle_exit_command,
    "run": handle_run_command,
    "runs": handle_runs_command,
    "save": handle_save_command,
    "topics": handle_topics_command,
    "triggers": handle_triggers_command,
    "use": handle_use_command,
    "var": handle_vars_command,
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
            source="var",
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
                raise ValueError("usage: var [--secret] name=value")
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


def resolve_var_key(state: ShellState, key: str) -> str:
    """Resolve unqualified variable keys through the active `use` context."""
    if "." in key or key.startswith("global."):
        return key
    if state.active_context:
        return f"{state.active_context}.{key}"
    return key
