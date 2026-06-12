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
    """Yield an unpacked plugin directory from a directory or zip submission."""
    source = source.resolve()
    if source.is_dir():
        yield locate_plugin_dir(source)
        return
    if not source.exists():
        raise FileNotFoundError(f"{source} not found")
    if source.suffix.lower() != ".zip":
        raise ValueError(f"{source} is not a directory or .zip file")
    with tempfile.TemporaryDirectory(prefix="bywaf-plugin-submission-") as tmp:
        extracted = Path(tmp) / "submission"
        extracted.mkdir()
        extract_zip_safely(source, extracted)
        yield locate_plugin_dir(extracted)


def extract_zip_safely(source: Path, destination: Path) -> None:
    """Extract a plugin zip while rejecting paths that escape destination."""
    with zipfile.ZipFile(source) as zipped:
        for member in zipped.infolist():
            target = destination / member.filename
            if member.filename.startswith("/") or ".." in Path(member.filename).parts:
                raise ValueError(f"{source} contains unsafe path: {member.filename}")
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError(f"{source} contains unsafe path: {member.filename}")
        zipped.extractall(destination)


def locate_plugin_dir(root: Path) -> Path:
    """Return the concrete plugin package directory within a submission."""
    if (root / "plugin.py").exists() and (root / "bywaf.plugin.toml").exists():
        return root
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
    """Copy the Bywaf source tree into a temp checkout for reproducible checks."""
    def ignore(dir_path: str, names: list[str]) -> set[str]:
        """Return whether a path should be ignored in plugin submissions."""
        del dir_path
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
    """Apply a plugin submission to a copied Bywaf checkout and validate it there."""
    submission = submission.resolve()
    manifest_key = manifest_key.resolve() if manifest_key is not None else None
    with tempfile.TemporaryDirectory(prefix="bywaf-plugin-checkout-") as tmp:
        tmp_path = Path(tmp)
        checkout = tmp_path / "bywaf"
        copy_checkout(checkout_source, checkout)
        plugin_root = checkout / ".plugin-submissions"
        plugin_root.mkdir()
        with materialized_plugin_submission(submission) as plugin_dir:
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
    """Run the copied checkout's checker and return its JSON report."""
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
    env["PYTHONPATH"] = str(checkout) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(command, cwd=checkout, env=env, text=True, capture_output=True, check=False)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        report = {
            "ok": False,
            "plugin": str(submission),
            "errors": ["temp checkout validation did not emit JSON"],
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    else:
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
    """Rewrite copied-checkout plugin paths in a nested report in place."""
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
