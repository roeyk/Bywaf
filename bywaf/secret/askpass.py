"""Desktop askpass helpers for interactive secret entry.

Provides a small Bywaf-owned askpass dialog with a reveal checkbox, plus
fallback support for SSH-compatible askpass helpers.

Used by:
- REPL variable commands: collect explicit secret values without echoing them.
- completion prompt setup: decide whether auto mode should use block input."""

from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import subprocess
from collections.abc import Mapping


ASKPASS_MODE = "askpass"
AUTO_SECRET_INPUT_MODE = "auto"
BLOCK_SECRET_INPUT_MODE = "block"
GETPASS_SECRET_INPUT_MODE = "getpass"
PLAINTEXT_SECRET_INPUT_MODE = "plaintext"
PLAIN_SECRET_INPUT_MODE = "plain"

DEFAULT_ASKPASS_HELPERS = (
    "ksshaskpass",
    "ssh-askpass",
    "ssh-askpass-fullscreen",
    "gnome-ssh-askpass",
)


class AskpassUnavailable(RuntimeError):
    """Raised when a desktop askpass prompt cannot be shown."""


class AskpassCancelled(RuntimeError):
    """Raised when the user closes or cancels the askpass prompt."""


def desktop_session_available(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether a graphical desktop session appears available."""
    env = environ or os.environ
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def builtin_askpass_available() -> bool:
    """Return whether the stdlib Tk dialog can probably be imported."""
    return importlib.util.find_spec("tkinter") is not None


def external_askpass_command(environ: Mapping[str, str] | None = None) -> list[str] | None:
    """Return a configured or discovered SSH-compatible askpass command."""
    env = environ or os.environ
    configured = env.get("BYWAF_ASKPASS") or env.get("SSH_ASKPASS")
    if configured:
        try:
            return shlex.split(configured)
        except ValueError:
            return None
    for helper in DEFAULT_ASKPASS_HELPERS:
        path = shutil.which(helper)
        if path:
            return [path]
    return None


def desktop_askpass_available(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether askpass can be attempted in the current environment."""
    if not desktop_session_available(environ):
        return False
    return builtin_askpass_available() or external_askpass_command(environ) is not None


def read_askpass_secret(prompt: str, *, environ: Mapping[str, str] | None = None) -> str:
    """Read one secret via desktop askpass, preferring the Bywaf dialog."""
    if not desktop_session_available(environ):
        raise AskpassUnavailable("no desktop session is available")
    if builtin_askpass_available():
        try:
            return read_tk_askpass_secret(prompt)
        except AskpassUnavailable:
            pass
    command = external_askpass_command(environ)
    if command is None:
        raise AskpassUnavailable("no askpass helper is available")
    return read_external_askpass_secret(command, prompt)


def read_external_askpass_secret(command: list[str], prompt: str) -> str:
    """Run an SSH-compatible askpass helper and return its stdout."""
    try:
        completed = subprocess.run(
            [*command, prompt],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AskpassUnavailable(str(exc)) from exc
    if completed.returncode != 0:
        raise AskpassCancelled("askpass helper did not return a secret")
    return completed.stdout.rstrip("\n")


def read_tk_askpass_secret(prompt: str) -> str:
    """Read one secret using a Tk dialog with a reveal checkbox."""
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError as exc:  # pragma: no cover - import depends on platform.
        raise AskpassUnavailable("tkinter is not available") from exc

    result: dict[str, str | None] = {"value": None}

    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - desktop availability varies.
        raise AskpassUnavailable(str(exc)) from exc

    root.title("Bywaf Secret")
    root.resizable(False, False)
    root.columnconfigure(0, weight=1)

    frame = ttk.Frame(root, padding=12)
    frame.grid(row=0, column=0, sticky="nsew")
    frame.columnconfigure(0, weight=1)

    ttk.Label(frame, text=prompt).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
    secret_var = tk.StringVar()
    reveal_var = tk.BooleanVar(value=False)
    entry = ttk.Entry(frame, textvariable=secret_var, show="*", width=42)
    entry.grid(row=1, column=0, columnspan=2, sticky="ew")

    def sync_reveal() -> None:
        entry.configure(show="" if reveal_var.get() else "*")

    ttk.Checkbutton(frame, text="Show input", variable=reveal_var, command=sync_reveal).grid(
        row=2,
        column=0,
        columnspan=2,
        sticky="w",
        pady=(8, 8),
    )

    def accept() -> None:
        result["value"] = secret_var.get()
        root.quit()

    def cancel() -> None:
        result["value"] = None
        root.quit()

    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, columnspan=2, sticky="e")
    ttk.Button(buttons, text="Cancel", command=cancel).grid(row=0, column=0, padx=(0, 6))
    ttk.Button(buttons, text="OK", command=accept).grid(row=0, column=1)

    root.protocol("WM_DELETE_WINDOW", cancel)
    root.bind("<Return>", lambda _event: accept())
    root.bind("<Escape>", lambda _event: cancel())
    entry.focus_set()
    root.update_idletasks()
    root.mainloop()
    root.destroy()

    if result["value"] is None:
        raise AskpassCancelled("secret prompt was cancelled")
    return result["value"]
