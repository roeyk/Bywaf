"""Shared fixtures for plugin-check tests.

Coverage focus: plugin check fixtures regression behavior.
"""

# pyright: reportMissingImports=false

from __future__ import annotations

from pathlib import Path


def write_plugin_fixture(
    root: Path,
    *,
    capabilities: tuple[str, ...],
    manifest_capabilities: tuple[str, ...] | None = None,
    consumes: tuple[str, ...] = (),
    manifest_consumes: tuple[str, ...] | None = None,
    emits: tuple[str, ...] = (),
    manifest_emits: tuple[str, ...] | None = None,
    imports: str = "",
    decorators: str = "",
    parser_import: str = "from bywaf.plugin import CommandSpec\n",
    run_body: str = "        yield {'ok': True}\n",
    manifest_extra: str = "",
) -> Path:
    """Test helper for write plugin fixture."""
    plugin_dir = root / "example"
    plugin_dir.mkdir(parents=True)
    capability_text = repr(capabilities)
    consumes_text = repr(consumes)
    emits_text = repr(emits)
    plugin_dir.joinpath("plugin.py").write_text(
        imports +
        parser_import +
        decorators +
        "class Example:\n"
        f"    spec = CommandSpec('example', 'example plugin', consumes={consumes_text}, emits={emits_text}, capabilities={capability_text})\n"
        "    def run(self, context, args, input_events):\n"
        f"{run_body}"
        "def plugin():\n"
        "    return Example()\n"
    )
    declared = capabilities if manifest_capabilities is None else manifest_capabilities
    manifest_capability_lines = "".join(f'  "{item}",\n' for item in declared)
    declared_emits = emits if manifest_emits is None else manifest_emits
    declared_consumes = consumes if manifest_consumes is None else manifest_consumes
    manifest_consumes_text = "consumes = [" + ", ".join(f'"{item}"' for item in declared_consumes) + "]\n" if declared_consumes else ""
    manifest_emits_text = "emits = [" + ", ".join(f'"{item}"' for item in declared_emits) + "]\n" if declared_emits else ""
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = [\n"
        f"{manifest_capability_lines}"
        "]\n"
        f"{manifest_consumes_text}"
        f"{manifest_emits_text}"
        f"{manifest_extra}"
    )
    return plugin_dir


def write_parser_mismatch_fixture(root: Path) -> Path:
    """Test helper for write parser mismatch fixture."""
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandletBase, commandlet, option\n"
        "@commandlet(name='example', description='example plugin')\n"
        "@option('target', 'target URL')\n"
        "class Example(CommandletBase):\n"
        "    def parser(self):\n"
        "        parser = super().parser()\n"
        "        parser.add_argument('--url')\n"
        "        return parser\n"
        "    def run(self, context, args, input_events):\n"
        "        parsed = self.parse_args(args)\n"
        "        yield {'target': parsed.target}\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = []\n"
        "options = [\n"
        "  { name = \"target\", description = \"target URL\" },\n"
        "]\n"
    )
    return plugin_dir


def write_decorated_factory_fixture(root: Path) -> Path:
    """Test helper for write decorated factory fixture."""
    plugin_dir = write_plugin_fixture(root, capabilities=())
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec, commandlet\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
        "@commandlet(name='wrong', description='wrong')\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    return plugin_dir


def write_multifile_plugin_fixture(root: Path) -> Path:
    plugin_dir = root / "example"
    plugin_dir.mkdir()
    plugin_dir.joinpath("plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "from .command import run\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield from run()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    plugin_dir.joinpath("command.py").write_text(
        "def run():\n"
        "    yield {'ok': True}\n"
    )
    plugin_dir.joinpath("bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
    )
    return plugin_dir


def write_manifest_signing_key(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_path = tmp_path / "manifest-signing.pem"
    public_path = tmp_path / "manifest-signing.pub.pem"
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def capture_stdout(fn):
    import contextlib
    import io

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = fn()
    if result not in (None, 0):
        raise AssertionError(f"expected successful return code, got {result}")
    return output.getvalue()
