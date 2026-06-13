"""Plugin submission materialization and temp-checkout validation helpers.

Used by:
- maintainer tools, documentation/report generation, and validation scripts.
- tests and release checks that exercise developer-facing tooling.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


CHECKOUT_IGNORE = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    ".bywaf",
    "build",
    "dist",
    ".pybuild",
}


@contextmanager
def materialized_plugin_submission(source: Path) -> Iterator[Path]:
    """Yield an unpacked plugin directory from a directory or zip submission.

    Called by: `scripts/plugin_check.py` for direct submissions and by
    `check_plugin_checkout()` before copying the plugin into a temp checkout.
    """
    source = source.resolve()
    if source.is_dir():
        # Directory submissions are already materialized; locate the concrete
        # plugin package and yield it without copying user files.
        yield locate_plugin_dir(source)
        return
    if not source.exists():
        raise FileNotFoundError(f"{source} not found")
    if source.suffix.lower() != ".zip":
        raise ValueError(f"{source} is not a directory or .zip file")
    with tempfile.TemporaryDirectory(prefix="bywaf-plugin-submission-") as tmp:
        extracted = Path(tmp) / "submission"
        extracted.mkdir()
        # Zip submissions are expanded into a short-lived directory so the rest
        # of the checker can treat zip and directory inputs the same way.
        extract_zip_safely(source, extracted)
        yield locate_plugin_dir(extracted)


def extract_zip_safely(source: Path, destination: Path) -> None:
    """Extract a plugin zip while rejecting paths that escape destination.

    Called by: `materialized_plugin_submission()` for `.zip` inputs before
    locating the submitted plugin package.
    """
    with zipfile.ZipFile(source) as zipped:
        for member in zipped.infolist():
            target = destination / member.filename
            # Reject absolute paths and `..` path components before extraction.
            # The resolved-path check below is a second guard against odd zip
            # member forms that still try to escape the destination.
            if member.filename.startswith("/") or ".." in Path(member.filename).parts:
                raise ValueError(f"{source} contains unsafe path: {member.filename}")
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError(f"{source} contains unsafe path: {member.filename}")
        zipped.extractall(destination)


def locate_plugin_dir(root: Path) -> Path:
    """Return the concrete plugin package directory within a submission.

    Called by: submission materialization helpers after a directory or zip has
    been made available on disk.
    """
    if (root / "plugin.py").exists() and (root / "bywaf.plugin.toml").exists():
        return root
    # Accept a zip with one enclosing folder, but reject archives that contain
    # multiple plugin packages because the checker must validate one provider
    # at a time.
    matches = sorted(
        path
        for path in root.rglob("bywaf.plugin.toml")
        if (path.parent / "plugin.py").exists() and "__pycache__" not in path.parts
    )
    if not matches:
        raise FileNotFoundError(f"{root} does not contain plugin.py and bywaf.plugin.toml")
    plugin_dirs = {path.parent for path in matches}
    if len(plugin_dirs) != 1:
        rendered = ", ".join(str(path.relative_to(root)) for path in sorted(plugin_dirs))
        raise ValueError(f"{root} contains multiple plugin directories: {rendered}")
    return next(iter(plugin_dirs))


def copy_checkout(source: Path, destination: Path) -> None:
    """Copy the Bywaf source tree into a temp checkout for reproducible checks.

    Called by: `check_plugin_checkout()` when `plugin_check --temp-checkout`
    validates a submitted plugin against a clean copy of this repository.
    """
    def ignore(dir_path: str, names: list[str]) -> set[str]:
        """Return checkout-local paths that should not be copied.

        Called by: `shutil.copytree()` for each directory during temp-checkout
        creation.
        """
        del dir_path
        # Keep source, tests, scripts, and docs, but skip caches, build output,
        # local runtime state, bytecode, and SQLite sidecar files.
        ignored = {name for name in names if name in CHECKOUT_IGNORE}
        ignored.update(name for name in names if name.endswith((".pyc", ".pyo", ".sqlite3", ".sqlite3-shm", ".sqlite3-wal")))
        return ignored

    shutil.copytree(source, destination, ignore=ignore)


def check_plugin_checkout(
    submission: Path,
    *,
    checkout_source: Path,
    manifest_key: Path | None = None,
    verify_manifest: bool = False,
    strict_inference: bool = False,
    include_graph: bool = False,
) -> dict[str, Any]:
    """Apply a plugin submission to a copied Bywaf checkout and validate it there.

    Called by: `scripts/plugin_check.py --temp-checkout` for external or
    LLM-generated plugin submissions that should be checked as if they were
    installed into a fresh Bywaf tree.
    """
    submission = submission.resolve()
    manifest_key = manifest_key.resolve() if manifest_key is not None else None
    with tempfile.TemporaryDirectory(prefix="bywaf-plugin-checkout-") as tmp:
        tmp_path = Path(tmp)
        checkout = tmp_path / "bywaf"
        copy_checkout(checkout_source, checkout)
        plugin_root = checkout / ".plugin-submissions"
        plugin_root.mkdir()
        with materialized_plugin_submission(submission) as plugin_dir:
            # Copy only the located plugin package into the temp checkout. This
            # avoids letting extra archive files influence imports or checker
            # path inference.
            target = plugin_root / plugin_dir.name
            shutil.copytree(plugin_dir, target)
        report = run_checkout_plugin_check(
            checkout,
            target,
            submission,
            manifest_key=manifest_key,
            verify_manifest=verify_manifest,
            strict_inference=strict_inference,
            include_graph=include_graph,
        )
        report["submission"] = str(submission)
        report["plugin"] = str(submission)
        report["temp_checkout"] = True
        return report


def run_checkout_plugin_check(
    checkout: Path,
    target: Path,
    submission: Path,
    *,
    manifest_key: Path | None,
    verify_manifest: bool,
    strict_inference: bool,
    include_graph: bool,
) -> dict[str, Any]:
    """Run the copied checkout's checker and return its JSON report.

    Called by: `check_plugin_checkout()` after the submission has been copied
    into `.plugin-submissions`.
    """
    # Invoke the checker script from inside the copied checkout so imports,
    # package data, and manifest-relative paths behave like a clean local tree.
    command = [
        sys.executable,
        str(checkout / "scripts" / "plugin_check.py"),
        str(target),
        "--json",
        "--no-temp-checkout",
    ]
    if manifest_key is not None:
        command.extend(["--manifest-key", str(manifest_key)])
    if verify_manifest:
        command.append("--verify")
    if strict_inference:
        command.append("--strict-inference")
    if include_graph:
        command.append("--graph")
    env = os.environ.copy()
    # Put the copied checkout at the front of PYTHONPATH so the subprocess does
    # not accidentally validate against the original working tree's modules.
    env["PYTHONPATH"] = str(checkout) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(command, cwd=checkout, env=env, text=True, capture_output=True, check=False)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Preserve stdout/stderr when JSON rendering fails; this makes temp
        # checkout failures debuggable from the outer plugin_check report.
        report = {
            "ok": False,
            "plugin": str(submission),
            "errors": ["temp checkout validation did not emit JSON"],
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    else:
        # The subprocess report naturally references temp-checkout paths.
        # Rewrite them back to the submitted path so feedback is actionable.
        remap_report_paths(report, str(target), str(submission))
    if result.returncode != 0:
        report["ok"] = False
    if result.stderr:
        report.setdefault("diagnostics", [])
        report.setdefault("warnings", [])
        report.setdefault("errors", []).append("temp checkout stderr: " + result.stderr.strip())
        report["ok"] = False
    return report


def remap_report_paths(value: Any, old_prefix: str, new_prefix: str) -> None:
    """Rewrite copied-checkout plugin paths in a nested report in place.

    Called by: `run_checkout_plugin_check()` after parsing the subprocess JSON
    report.
    """
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if isinstance(item, str):
                value[key] = item.replace(old_prefix, new_prefix)
            else:
                remap_report_paths(item, old_prefix, new_prefix)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                value[index] = item.replace(old_prefix, new_prefix)
            else:
                remap_report_paths(item, old_prefix, new_prefix)
