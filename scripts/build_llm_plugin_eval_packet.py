#!/usr/bin/env python3
"""Build a portable LLM plugin-author evaluation packet.

The packet gives external LLMs enough repo-grounded material to attempt a
plugin without browsing the whole GitHub tree. It also gives them exact GitHub
blob URLs to use in proof tables.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path


REPO_URL = "https://github.com/roeyk/Bywaf"

PACKET_FILES = (
    "README.md",
    "USAGE.md",
    "docs/plugin_author/README.md",
    "docs/plugin_author/fundamentals.md",
    "docs/plugin_author/commandlet-api.md",
    "docs/plugin_author/event-schemas.md",
    "docs/plugin_author/testing-and-guidelines.md",
    "docs/plugin_skeletons/README.md",
    "docs/plugin_skeletons/native_minimal/plugin.py",
    "docs/plugin_skeletons/native_minimal/bywaf.plugin.toml",
    "docs/plugin_skeletons/native_vulnerability/plugin.py",
    "docs/plugin_skeletons/native_vulnerability/command.py",
    "docs/plugin_skeletons/native_vulnerability/detect.py",
    "docs/plugin_skeletons/native_vulnerability/findings.py",
    "docs/plugin_skeletons/native_vulnerability/models.py",
    "docs/plugin_skeletons/native_vulnerability/bywaf.plugin.toml",
    "docs/plugin_skeletons/native_vulnerability/tests/test_detect.py",
    "docs/plugin_skeletons/library_backed/plugin.py",
    "docs/plugin_skeletons/library_backed/bywaf.plugin.toml",
    "docs/MANIFEST_SPECIFICATION.md",
    "docs/EVENT_MODEL.md",
    "docs/CAPABILITY_MODEL.md",
    "docs/FRAMEWORK_SURFACE.md",
    "bywaf/plugins/plugins.toml",
    "bywaf/plugins/http/http_probe.py",
    "bywaf/plugins/http/http_probe.plugin.toml",
    "bywaf/plugins/http/webfin.py",
    "bywaf/plugins/http/webfin.plugin.toml",
    "bywaf/plugins/http/http_headers/__init__.py",
    "bywaf/plugins/http/http_headers/command.py",
    "bywaf/plugins/http/http_headers/models.py",
    "bywaf/plugins/http/http_headers/bywaf.plugin.toml",
    "bywaf/plugins/http/repo_exposure/__init__.py",
    "bywaf/plugins/http/repo_exposure/command.py",
    "bywaf/plugins/http/repo_exposure/bywaf.plugin.toml",
    "bywaf/event/schema_objects.py",
    "tests/test_http_probe.py",
    "tests/test_mvp_plugin_suite.py",
    "tests/test_registry_completion.py",
)


PROMPT = """# Bywaf External Plugin Author Evaluation

You are an external developer with no prior knowledge of Bywaf.

Repository:
https://github.com/roeyk/Bywaf

You have been given a curated repo access packet. Use the files in this packet
and the GitHub blob URLs in `file-list.md` as your source of truth.

Your task is to write a new Bywaf plugin from the provided documentation and
source examples only. Do not ask how Bywaf works unless the provided docs and
files are genuinely insufficient.

Skeleton-first rule:
Choose the closest skeleton under `repo-files/docs/plugin_skeletons/`, copy its
layout, and fill in that structure. Do not invent a plugin layout from scratch.
For this task, start from `native_minimal` if the plugin stays very small, or
from `native_vulnerability` if you split detection, command orchestration,
finding/event payloads, models, and tests. Preserve required files such as
`plugin.py` and `bywaf.plugin.toml`, including required manifest fields, unless
you can prove a change from the provided docs.

Before writing any code, do a repository reconnaissance pass.

Reconnaissance requirements:
1. Read the plugin-author documentation.
2. Read `docs/plugin_skeletons/README.md`.
3. Choose one skeleton and explain why it is the closest fit.
4. Read every file in the chosen skeleton.
5. Read at least two existing plugins that are similar to the requested plugin.
6. Read the manifest specification or existing plugin manifests.
7. Read relevant tests for similar plugins.
8. Identify the framework helper APIs you intend to use.
9. Identify the event schemas/topics you intend to publish or consume.
10. Explicitly list the files you read and the facts you learned from each.

Critical rule: before writing code, every import path, manifest key, capability,
event topic, helper API, and test helper you plan to use must be proven by
citing an exact GitHub blob URL with a line anchor.

Acceptable proof example:
https://github.com/roeyk/Bywaf/blob/main/bywaf/plugins/http/http_probe.py#L28

If you cannot prove an item, do not use it. Do not provide code until after
this proof table.

Proof table columns:
- planned item
- why you need it
- exact GitHub blob URL with line anchor proving it exists
- pass/fail
- replacement if failed

Goal:
Create a bundled plugin named `http_title` that probes HTTP/HTTPS services and
records discovered page titles.

Expected operator behavior:
- `http_title target=http://127.0.0.1:8080`
- `http_title target=https://example.com`
- `ports | http_title`
- It should accept named arguments, not argparse-style long options:
  - `target=`
  - `timeout=`
  - `scheme=`
- If piped from previous events, it should consume relevant normalized events
  such as open HTTP/HTTPS ports where possible.
- It should publish normalized events for discovered web titles.
- It should attach raw response metadata/output as artifacts if the framework
  supports that pattern.
- It should declare its manifest, capabilities, database actions, schemas/topics,
  variables, and plugin metadata correctly.
- It should include tests using fixtures or local fake responses, not live
  internet dependencies.
- It should follow the existing plugin style and helper APIs in the repository.

Deliverables:
1. A reconnaissance summary listing which docs/source/test files you read and
   what each taught you.
2. The proof table.
3. A list of files you would add or modify.
4. The actual code changes.
5. Tests.
6. Any documentation updates needed.
7. Any places where the Bywaf plugin surface was unclear or forced guessing.
8. `VALIDATION.md` showing the test/check/fix loop you ran before finalizing.

After writing the plugin, you must test it in a real Bywaf checkout before
producing the final answer or final zip.

Required validation loop:
1. Apply your proposed files to a fresh checkout or temporary copy of the Bywaf
   repository.
2. Run:
   - `python3 scripts/plugin_check.py <plugin-dir> --strict-inference --llm-feedback`
   - `PYTHONPATH=. python3 -m pytest -q tests/test_http_title.py`
   - `PYTHONPATH=. python3 -m pytest -q tests/test_registry_completion.py`
3. If any command fails, fix the plugin and rerun the failing command.
4. Do not produce the final code/zip until all required commands pass.
5. Include `VALIDATION.md` with:
   - exact commands run
   - pass/fail output summaries
   - failures encountered
   - fixes made after each failure

Important constraints:
- Start from a provided skeleton. Keep its required manifest fields and plugin
  factory shape unless a cited repository line proves a different shape is
  required.
- Do not use raw database access unless the docs explicitly say that is correct.
- Do not invent framework APIs without checking existing code.
- Do not infer the plugin API from general Python plugin patterns; use this
  repository's docs and examples.
- Do not make network tests depend on the public internet.
- Keep the plugin small and idiomatic.
- Prefer framework-provided helpers over ad hoc parsing or storage.
- If the correct event schema/topic is unclear, say so and choose the least
  surprising option.

After implementing, summarize:
- What was easy to discover.
- What was hard to discover.
- What API or documentation improvements would make plugin authoring easier.

Self-audit your plugin against the Bywaf repository conventions:
1. Manifest correctness.
2. Capability declarations.
3. Database action classification.
4. Event schema/topic usage.
5. Artifact usage.
6. Input event consumption.
7. Named-argument behavior.
8. Tests and fixture quality.
9. Whether runtime view commands would be polluted by this plugin.
10. Any places where you guessed.
11. Whether every framework API you used exists in the repository.
12. Whether your implementation followed the docs/examples you cited before coding.

Any API, import, manifest key, capability, event topic, or test helper without
a GitHub blob URL proof line must be marked failed.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("../bywaf-llm-plugin-eval-packet"),
        help="packet output directory base; timestamp is appended by default",
    )
    parser.add_argument("--ref", default="main", help="GitHub ref used in blob URLs")
    parser.add_argument("--force", action="store_true", help="replace an existing output directory")
    parser.add_argument("--no-timestamp", action="store_true", help="use --output exactly instead of appending a timestamp")
    return parser.parse_args()


def repo_root() -> Path:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, text=True, capture_output=True)
    return Path(result.stdout.strip())


def github_url(path: str, ref: str) -> str:
    return f"{REPO_URL}/blob/{ref}/{path}"


def copy_packet_files(root: Path, output: Path) -> list[str]:
    copied: list[str] = []
    sources_dir = output / "repo-files"
    for relative in PACKET_FILES:
        source = root / relative
        if not source.exists():
            raise FileNotFoundError(relative)
        if source.is_symlink():
            raise RuntimeError(f"refusing to package symlink: {relative}")
        resolved = source.resolve()
        if root.resolve() not in resolved.parents and resolved != root.resolve():
            raise RuntimeError(f"refusing to package path outside repo: {relative}")
        destination = sources_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(relative)
    return copied


def write_file_list(output: Path, files: list[str], ref: str) -> None:
    lines = [
        "# Curated Repository Files",
        "",
        "Use these exact GitHub blob URLs when citing proof lines.",
        "",
    ]
    lines.extend(f"- [{path}]({github_url(path, ref)})" for path in files)
    lines.append("")
    (output / "file-list.md").write_text("\n".join(lines), encoding="utf-8")


def write_tree(output: Path) -> None:
    paths = sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file())
    (output / "packet-tree.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")


def write_prompt(output: Path) -> None:
    (output / "PROMPT.md").write_text(PROMPT, encoding="utf-8")


def write_security_note(output: Path) -> None:
    lines = [
        "# Security Notes",
        "",
        "This packet is intended for upload to external LLM systems.",
        "",
        "Included:",
        "- curated public Bywaf documentation",
        "- curated public Bywaf plugin examples",
        "- curated public Bywaf tests",
        "- the evaluation prompt and exact GitHub blob URL list",
        "",
        "Not included:",
        "- `.bywaf/` project databases",
        "- artifact databases or artifact bodies",
        "- secrets, credentials, SSH keys, API keys, cookies, or tokens",
        "- local operator notes outside this packet",
        "- client data or scan output",
        "",
        "Before uploading a regenerated packet, inspect `packet-tree.txt` and",
        "confirm it contains only expected public repository files.",
        "",
    ]
    (output / "SECURITY.md").write_text("\n".join(lines), encoding="utf-8")


def zip_packet(output: Path) -> Path:
    archive = output.with_suffix(".zip")
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(output.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(output.parent))
    return archive


def timestamped_output(path: Path, *, enabled: bool) -> Path:
    """Append a timestamp to packet output paths unless disabled."""
    if not enabled:
        return path
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return path.with_name(f"{path.name}-{stamp}")


def main() -> int:
    args = parse_args()
    root = repo_root()
    output = timestamped_output(args.output.expanduser(), enabled=not args.no_timestamp)
    if not output.is_absolute():
        output = (root / output).resolve()
    if output.exists():
        if not args.force:
            raise SystemExit(f"{output} exists; use --force to replace it")
        shutil.rmtree(output)
    output.mkdir(parents=True)
    files = copy_packet_files(root, output)
    write_file_list(output, files, args.ref)
    write_prompt(output)
    write_security_note(output)
    write_tree(output)
    archive = zip_packet(output)
    print(f"packet={output}")
    print(f"archive={archive}")
    print(f"files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
