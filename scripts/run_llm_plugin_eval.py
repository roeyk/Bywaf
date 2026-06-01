#!/usr/bin/env python3
"""Run the plugin-author evaluation prompt against external LLM APIs.

API keys are read from environment variables and are never written to disk:

- OPENAI_API_KEY for OpenAI-compatible ChatGPT models
- GEMINI_API_KEY for Gemini
- XAI_API_KEY for xAI/Grok OpenAI-compatible API

The script saves provider responses and request metadata under a timestamped
output directory so repeated runs can be compared.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PACKET = Path("../bywaf-llm-plugin-eval-packet")
DEFAULT_OUTPUT = Path("../bywaf-llm-plugin-eval-runs")

PROVIDERS = ("openai", "gemini", "xai")


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    api_key_env: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET, help="packet directory containing PROMPT.md and repo-files/")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="base output directory for timestamped run results")
    parser.add_argument("--provider", choices=PROVIDERS, action="append", help="provider to run; repeatable; default: all configured")
    parser.add_argument("--openai-model", default="gpt-4.1", help="OpenAI model name")
    parser.add_argument("--gemini-model", default="gemini-2.5-pro", help="Gemini model name")
    parser.add_argument("--xai-model", default="grok-3", help="xAI/Grok model name")
    parser.add_argument("--max-repo-file-chars", type=int, default=12000, help="truncate each included repo file to this many chars; 0 disables truncation")
    parser.add_argument("--dry-run", action="store_true", help="write prompts/metadata but do not call APIs")
    return parser.parse_args()


def repo_root() -> Path:
    import subprocess

    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, text=True, capture_output=True)
    return Path(result.stdout.strip())


def resolve_path(root: Path, path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return (root / expanded).resolve()


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def provider_configs(args: argparse.Namespace) -> dict[str, ProviderConfig]:
    return {
        "openai": ProviderConfig("openai", args.openai_model, "OPENAI_API_KEY"),
        "gemini": ProviderConfig("gemini", args.gemini_model, "GEMINI_API_KEY"),
        "xai": ProviderConfig("xai", args.xai_model, "XAI_API_KEY"),
    }


def read_packet_prompt(packet: Path, max_repo_file_chars: int) -> str:
    prompt_path = packet / "PROMPT.md"
    if not prompt_path.exists():
        raise FileNotFoundError(prompt_path)
    parts = [prompt_path.read_text(encoding="utf-8"), "\n\n# Curated Packet Files\n"]
    repo_files = packet / "repo-files"
    for file_path in sorted(repo_files.rglob("*")):
        if not file_path.is_file():
            continue
        relative = file_path.relative_to(repo_files).as_posix()
        text = file_path.read_text(encoding="utf-8", errors="replace")
        truncated = False
        if max_repo_file_chars and len(text) > max_repo_file_chars:
            text = text[:max_repo_file_chars]
            truncated = True
        parts.append(f"\n## repo-files/{relative}\n")
        parts.append("```text\n")
        parts.append(text)
        if truncated:
            parts.append("\n...[truncated by evaluation harness]...\n")
        parts.append("\n```\n")
    return "".join(parts)


def http_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout_seconds: int = 180) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc


def call_openai_like(config: ProviderConfig, prompt: str, *, base_url: str) -> dict[str, Any]:
    api_key = require_env(config.api_key_env)
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": "You are a careful software engineer. Follow the user's proof-before-code instructions exactly."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
    }
    return http_json(
        f"{base_url.rstrip('/')}/chat/completions",
        {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        payload,
    )


def call_gemini(config: ProviderConfig, prompt: str) -> dict[str, Any]:
    api_key = require_env(config.api_key_env)
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
        },
    }
    return http_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{config.model}:generateContent?key={api_key}",
        {"Content-Type": "application/json"},
        payload,
    )


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing {name}")
    return value


def extract_text(provider: str, response: dict[str, Any]) -> str:
    if provider in {"openai", "xai"}:
        choices = response.get("choices") or []
        if not choices:
            return ""
        return str(choices[0].get("message", {}).get("content", ""))
    if provider == "gemini":
        candidates = response.get("candidates") or []
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "\n".join(str(part.get("text", "")) for part in parts)
    return json.dumps(response, indent=2)


def run_provider(config: ProviderConfig, prompt: str) -> dict[str, Any]:
    if config.name == "openai":
        return call_openai_like(config, prompt, base_url="https://api.openai.com/v1")
    if config.name == "xai":
        return call_openai_like(config, prompt, base_url="https://api.x.ai/v1")
    if config.name == "gemini":
        return call_gemini(config, prompt)
    raise ValueError(config.name)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    root = repo_root()
    packet = resolve_path(root, args.packet)
    output_base = resolve_path(root, args.output)
    run_dir = output_base / timestamp()
    run_dir.mkdir(parents=True, exist_ok=False)
    prompt = read_packet_prompt(packet, args.max_repo_file_chars)
    (run_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

    configs = provider_configs(args)
    selected = args.provider or [name for name, config in configs.items() if os.environ.get(config.api_key_env)]
    if not selected:
        raise SystemExit("no providers selected and no provider API keys found")

    manifest = {
        "packet": str(packet),
        "providers": selected,
        "created": datetime.now().isoformat(),
        "dry_run": args.dry_run,
        "max_repo_file_chars": args.max_repo_file_chars,
    }
    write_json(run_dir / "run.json", manifest)

    for provider in selected:
        config = configs[provider]
        provider_dir = run_dir / provider
        provider_dir.mkdir()
        metadata = {
            "provider": config.name,
            "model": config.model,
            "api_key_env": config.api_key_env,
            "started": datetime.now().isoformat(),
            "dry_run": args.dry_run,
        }
        write_json(provider_dir / "metadata.json", metadata)
        if args.dry_run:
            (provider_dir / "response.md").write_text("", encoding="utf-8")
            continue
        started = time.monotonic()
        try:
            response = run_provider(config, prompt)
            metadata["duration_seconds"] = round(time.monotonic() - started, 3)
            metadata["ok"] = True
            write_json(provider_dir / "raw-response.json", response)
            (provider_dir / "response.md").write_text(extract_text(provider, response), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - preserve provider failures in run output.
            metadata["duration_seconds"] = round(time.monotonic() - started, 3)
            metadata["ok"] = False
            metadata["error"] = str(exc)
            (provider_dir / "error.txt").write_text(str(exc), encoding="utf-8")
        finally:
            metadata["finished"] = datetime.now().isoformat()
            write_json(provider_dir / "metadata.json", metadata)

    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
