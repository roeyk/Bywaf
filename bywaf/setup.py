"""First-run setup helpers.

Provides the explicit `bywaf --setup` path and first-run configuration
detection without making setup mandatory for ad hoc exploration.

Used by:
- bywaf.app: route explicit setup and show the interactive first-run notice.
- tests: verify user-local setup state under an isolated HOME.
"""

from __future__ import annotations

from dataclasses import dataclass
import getpass
from pathlib import Path
import sys

from .db import EventStore, sqlcipher_available
from .keyring import KeyRecord, default_key_paths, generate_key
from .projects import ProjectPaths, create_project, project_paths, projects_root, validate_project_name
from .secret.askpass import ASKPASS_MODE, AskpassCancelled, AskpassUnavailable, read_askpass_secret
from .secret.input import BLOCK_SECRET_INPUT_MODE, GETPASS_SECRET_INPUT_MODE, effective_secret_input_mode
from .toml_support import load_data_text


DEFAULT_PROJECT_NAME = "default"
DEFAULT_SECRET_INPUT_MODE = "auto"
# Setup creates bundle-signing keys by default because evidence bundle
# integrity is an operator-facing setup concern.
SETUP_SIGNING_KEYS = (
    "bundle-signing",
)
# Plugin signing is still hidden behind an explicit setup flag, so the normal
# first-run path does not create publisher trust material unless requested.
PLUGIN_SIGNING_KEYS = (
    "plugin-manifest-signing",
    "plugin-catalog-signing",
)
USER_CONFIG_TEMPLATE = """# Bywaf user configuration.
# Project data lives under ~/.bywaf/projects/<name>/.

[setup]
version = 1
default_project = "default"

[variables]
"secret.input-mode" = "auto"
"""


@dataclass(frozen=True, slots=True)
class SetupResult:
    """Paths created or confirmed by one setup run.

    Constructed by: `setup_result()`.
    Used by: `run_setup()` callers and `print_setup_result()` for the
    operator-facing setup summary.
    """

    config: Path
    project: ProjectPaths
    created_config: bool
    created_project: bool
    encrypted: bool
    secret_input_mode: str
    generated_keys: tuple[str, ...]
    existing_keys: tuple[str, ...]
    recorded_event: bool


@dataclass(frozen=True, slots=True)
class SetupChoices:
    """Interactive setup choices collected before filesystem changes.

    Constructed by: `collect_setup_choices()` before durable state is created.
    Used by: setup-state creation and audit-event publication so prompts,
    filesystem changes, and event payloads stay in one consistent transaction.
    """

    project_name: str
    encrypted: bool
    passphrase: str | None
    secret_input_mode: str
    generated_keys: tuple[KeyRecord, ...]
    existing_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SetupState:
    """Filesystem state created or confirmed during setup.

    Constructed by: `create_setup_state()`.
    Used by: `publish_setup_events()` and `setup_result()` after setup has
    touched user-local configuration and project directories.
    """

    config: Path
    project: ProjectPaths
    created_config: bool
    created_project: bool


def user_state_root() -> Path:
    """Return the durable per-user Bywaf state directory.

    Called by: setup helpers that manage user-local state under `~/.bywaf`.
    """
    return Path.home() / ".bywaf"


def user_config_path() -> Path:
    """Return the durable per-user setup/configuration file path.

    Called by: setup detection, setup creation, and configured-secret lookup.
    """
    return user_state_root() / "config.toml"


def setup_missing() -> bool:
    """Return whether first-run setup state is absent.

    Called by: app startup before showing the optional first-run notice.
    """
    return not user_config_path().exists()


def interactive_stdio() -> bool:
    """Return whether the current process can show friendly interactive text.

    Called by: first-run notice and setup prompting paths.
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def first_run_notice_needed(*, quiet: bool, interactive: bool | None = None) -> bool:
    """Return whether startup should show the friendly first-run setup notice.

    Called by: app startup before entering the REPL.
    """
    if quiet or not setup_missing():
        return False
    return interactive_stdio() if interactive is None else interactive


def print_first_run_notice() -> None:
    """Print the interactive first-run setup notice.

    Called by: app startup when setup is missing and stdio is interactive.
    """
    print("No Bywaf configuration found.")
    print("Run `bywaf --setup` to create one, or continue with defaults.")


def run_setup(
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    output: bool = True,
    include_plugin_signing_keys: bool = False,
) -> SetupResult:
    """Create durable user setup files and a default project if needed.

    Called by: CLI app dispatch for `bywaf --setup`.
    """
    # Keep all prompts before filesystem writes so cancelled setup does not
    # leave partial config/project state behind.
    choices = collect_setup_choices(
        project_name=project_name,
        include_plugin_signing_keys=include_plugin_signing_keys,
    )
    # Filesystem creation and audit publication are separate phases; tests can
    # then prove failed key/encryption prompts do not publish success events.
    state = create_setup_state(choices.project_name)
    recorded_event = publish_setup_events(state, choices)
    result = setup_result(state, choices, recorded_event=recorded_event)
    if output:
        print_setup_result(result)
    return result


def collect_setup_choices(
    *,
    project_name: str,
    include_plugin_signing_keys: bool,
) -> SetupChoices:
    """Collect setup options before creating durable files.

    Called by: `run_setup()` before any user-local setup files are created.
    """
    interactive = interactive_stdio()
    if interactive:
        project_name = prompt_project_name(project_name)
    secret_input_mode = configured_secret_input_mode()
    # Encryption and signing keys both need secrets, but they are independent
    # choices: encrypted project storage can be enabled without creating keys.
    encrypted, passphrase = setup_encryption_choice(project_name, interactive=interactive, mode=secret_input_mode)
    generated_keys, existing_keys = setup_signing_key_choices(
        interactive=interactive,
        include_plugin_signing_keys=include_plugin_signing_keys,
        mode=secret_input_mode,
    )
    return SetupChoices(
        project_name=project_name,
        encrypted=encrypted,
        passphrase=passphrase,
        secret_input_mode=secret_input_mode,
        generated_keys=generated_keys,
        existing_keys=existing_keys,
    )


def setup_encryption_choice(project_name: str, *, interactive: bool, mode: str) -> tuple[bool, str | None]:
    """Return whether setup should create an encrypted project database.

    Called by: `collect_setup_choices()`.
    """
    if not interactive or not confirm("Create encrypted project database?", default=False):
        return False, None
    database = project_paths(project_name).database
    # Existing SQLite files cannot be transparently converted here; refusing is
    # clearer than silently leaving the project unencrypted.
    if database.exists():
        raise ValueError(f"cannot enable encryption during setup because project database already exists: {database}")
    return True, prompt_setup_passphrase(database, mode=mode)


def setup_signing_key_choices(
    *,
    interactive: bool,
    include_plugin_signing_keys: bool,
    mode: str,
) -> tuple[tuple[KeyRecord, ...], tuple[str, ...]]:
    """Return signing keys generated or found during interactive setup.

    Called by: `collect_setup_choices()`.
    """
    generated_keys: tuple[KeyRecord, ...] = ()
    existing_keys: tuple[str, ...] = ()
    if interactive and confirm("Create local signing key for evidence bundles?", default=False):
        generated_keys, existing_keys = generate_setup_signing_keys(mode=mode)
    # Plugin publisher keys are opt-in so ordinary operators are not asked
    # about plugin trust material during their first setup run.
    if interactive and include_plugin_signing_keys and confirm("Create plugin manifest/catalog signing keys?", default=False):
        plugin_generated, plugin_existing = generate_setup_signing_keys(
            mode=mode,
            key_names=PLUGIN_SIGNING_KEYS,
        )
        generated_keys = (*generated_keys, *plugin_generated)
        existing_keys = (*existing_keys, *plugin_existing)
    return generated_keys, existing_keys


def create_setup_state(project_name: str) -> SetupState:
    """Create user config and project directories for setup.

    Called by: `run_setup()` after all prompts have completed.
    """
    root = user_state_root()
    config = user_config_path()
    # User config is global; project state is separate so `project=<name>` can
    # switch databases/history later without rewriting global setup metadata.
    root.mkdir(parents=True, exist_ok=True)
    created_config = not config.exists()
    if created_config:
        config.write_text(USER_CONFIG_TEMPLATE, encoding="utf-8")

    projects_root().mkdir(parents=True, exist_ok=True)
    project = project_paths(project_name)
    created_project = not project.path.exists()
    if created_project:
        project = create_project(project_name)
    return SetupState(config=config, project=project, created_config=created_config, created_project=created_project)


def publish_setup_events(state: SetupState, choices: SetupChoices) -> bool:
    """Publish setup audit events into the newly active project database.

    Called by: `run_setup()` after config/project files exist.
    """
    db = EventStore(state.project.database, passphrase=choices.passphrase)
    # The setup.completed event is the durable audit record for first-run state;
    # it is intentionally written into the project database just created.
    db.publish(
        "setup.completed",
        {
            "config": str(state.config),
            "project": state.project.name,
            "project_path": str(state.project.path),
            "database": str(state.project.database),
            "encrypted": choices.encrypted,
            "created_config": state.created_config,
            "created_project": state.created_project,
            "secret_input_mode": choices.secret_input_mode,
            "generated_keys": [key_record_payload(record) for record in choices.generated_keys],
            "existing_keys": list(choices.existing_keys),
        },
        "framework",
    )
    if choices.generated_keys or choices.existing_keys:
        # Key details are split into a second event so consumers can subscribe
        # to key-setup activity without parsing every setup.completed payload.
        db.publish(
            "setup.keys_configured",
            {
                "generated_keys": [key_record_payload(record) for record in choices.generated_keys],
                "existing_keys": list(choices.existing_keys),
                "key_root": str(default_key_paths().root),
            },
            "framework",
        )
    return True


def setup_result(state: SetupState, choices: SetupChoices, *, recorded_event: bool) -> SetupResult:
    """Return the public setup result from internal setup state.

    Called by: `run_setup()` before optional summary printing.
    """
    return SetupResult(
        config=state.config,
        project=state.project,
        created_config=state.created_config,
        created_project=state.created_project,
        encrypted=choices.encrypted,
        secret_input_mode=choices.secret_input_mode,
        generated_keys=tuple(record.name for record in choices.generated_keys),
        existing_keys=choices.existing_keys,
        recorded_event=recorded_event,
    )


def print_setup_result(result: SetupResult) -> None:
    """Print a compact operator-facing setup summary.

    Called by: `run_setup()` unless setup was requested with quiet output.
    """
    config_status = "created" if result.created_config else "exists"
    project_status = "created" if result.created_project else "exists"
    print(f"Bywaf configuration {config_status}: {result.config}")
    print(f"Default project {project_status}: {result.project.path}")
    storage = "encrypted SQLCipher" if result.encrypted else "plaintext SQLite"
    print(f"Project database: {result.project.database} ({storage})")
    print(f"Project config: {result.project.config}")
    print(f"Project history: {result.project.history}")
    print("Artifact databases are created beside the active event database when artifacts are attached.")
    if result.generated_keys:
        print(f"Generated signing keys: {', '.join(result.generated_keys)}")
    if result.existing_keys:
        print(f"Existing signing keys left unchanged: {', '.join(result.existing_keys)}")
    print(f"Signing keys live under {default_key_paths().root}.")
    print(f"Use `bywaf project={result.project.name}` to start in this project.")


def prompt_project_name(default: str) -> str:
    """Prompt for a setup project name, returning the validated value.

    Called by: `collect_setup_choices()` in interactive setup mode.
    """
    while True:
        response = input(f"Project name [{default}]: ").strip() or default
        try:
            return validate_project_name(response)
        except ValueError as exc:
            print(f"error: {exc}")


def confirm(prompt: str, *, default: bool) -> bool:
    """Prompt for a yes/no setup choice.

    Called by: interactive setup choice helpers.
    """
    suffix = "[Y/n]" if default else "[y/N]"
    response = input(f"{prompt} {suffix}: ").strip().casefold()
    if not response:
        return default
    return response in {"y", "yes"}


def configured_secret_input_mode() -> str:
    """Return the configured setup secret-input mode from user config.

    Called by: `collect_setup_choices()` before prompting for setup secrets.
    """
    config = user_config_path()
    if not config.exists():
        return DEFAULT_SECRET_INPUT_MODE
    data = load_data_text(config.read_text(encoding="utf-8"), suffix=config.suffix, label=str(config))
    values = data.get("variables", data)
    # Old or hand-written configs may contain malformed variables sections; in
    # that case setup falls back to the safe default instead of failing early.
    if not isinstance(values, dict):
        return DEFAULT_SECRET_INPUT_MODE
    return str(values.get("secret.input-mode", DEFAULT_SECRET_INPUT_MODE))


def prompt_setup_passphrase(path: Path, *, mode: str) -> str:
    """Prompt twice for an encrypted setup database passphrase.

    Called by: `setup_encryption_choice()` after SQLCipher availability checks.
    """
    if not sqlcipher_available():
        raise RuntimeError("encrypted project setup requires the sqlcipher3-binary package")
    first = read_secret(f"Create passphrase for encrypted project database {path}: ", mode=mode)
    second = read_secret("Confirm encrypted project database passphrase: ", mode=mode)
    if first != second:
        raise ValueError("passphrases do not match")
    if not first:
        raise ValueError("encrypted project database passphrase cannot be empty")
    return first


def generate_setup_signing_keys(
    *,
    mode: str,
    key_names: tuple[str, ...] = SETUP_SIGNING_KEYS,
) -> tuple[tuple[KeyRecord, ...], tuple[str, ...]]:
    """Generate the optional setup signing keys without overwriting existing keys.

    Called by: `setup_signing_key_choices()` for bundle and optional plugin
    signing material.
    """
    print("Signing keys are encrypted private keys used later for bundle integrity and plugin trust.")
    print(f"They will be stored under {default_key_paths().root}.")
    passphrase = prompt_new_secret(
        "Create passphrase for local signing keys: ",
        "Confirm local signing key passphrase: ",
        mode=mode,
    )
    generated: list[KeyRecord] = []
    existing: list[str] = []
    for name in key_names:
        try:
            generated.append(generate_key(name, passphrase, scope="user"))
        except FileExistsError:
            # Existing keys are reported but not overwritten; setup should be
            # safe to rerun on an already configured account.
            existing.append(name)
    return tuple(generated), tuple(existing)


def prompt_new_secret(first_prompt: str, confirm_prompt: str, *, mode: str) -> str:
    """Prompt for one new secret and confirmation.

    Called by: setup encryption and signing-key prompt paths.
    """
    first = read_secret(first_prompt, mode=mode)
    second = read_secret(confirm_prompt, mode=mode)
    if first != second:
        raise ValueError("passphrases do not match")
    if not first:
        raise ValueError("passphrase cannot be empty")
    return first


def read_secret(prompt: str, *, mode: str) -> str:
    """Read a setup secret without using an echoing terminal prompt.

    Called by: `prompt_setup_passphrase()` and `prompt_new_secret()`.
    """
    active_mode = effective_secret_input_mode(mode)
    if active_mode == ASKPASS_MODE:
        try:
            # GUI askpass is preferred when configured, but setup can fall back
            # to getpass if the helper is unavailable in this environment.
            return read_askpass_secret(prompt)
        except AskpassUnavailable as exc:
            print(f"askpass secret input unavailable ({exc}); falling back to getpass", file=sys.stderr)
            return getpass.getpass(prompt)
        except AskpassCancelled:
            raise
    if active_mode == BLOCK_SECRET_INPUT_MODE:
        print("block secret input is available inside the Bywaf interpreter; setup is using getpass.", file=sys.stderr)
    elif active_mode != GETPASS_SECRET_INPUT_MODE:
        print(f"secret input mode {active_mode!r} is not safe for setup; using getpass.", file=sys.stderr)
    return getpass.getpass(prompt)


def key_record_payload(record: KeyRecord) -> dict[str, str]:
    """Return audit-safe key metadata for setup events.

    Called by: `publish_setup_events()` for setup audit payloads.
    """
    return {
        "name": record.name,
        "scope": record.scope,
        "algorithm": record.algorithm,
        "fingerprint": record.fingerprint,
        "public_path": str(record.public_path or ""),
        "private_path": str(record.private_path or ""),
    }
