"""Shared helpers for packaging install-path tests.

Coverage focus: shared fixtures and test doubles for packaging install tests.
"""

# pyright: reportMissingImports=false

from pathlib import Path
import importlib.util

from unittest.mock import patch

from bywaf.registry import plugin_manifest_signature_block
from scripts.plugin_catalog import build_catalog, sign_catalog, write_json


def cryptography_available() -> bool:
    return importlib.util.find_spec("cryptography") is not None


PLUGIN_TEMPLATE = """\
from bywaf.plugin import CommandSpec


class {class_name}:
    spec = CommandSpec({name!r}, {description!r}, emits=({topic!r},))

    def run(self, context, args, input_events):
        yield {{"source": {source!r}}}


def plugin():
    return {class_name}()
"""


def write_plugin(root: Path, entry: str, name: str, source: str) -> Path:
    """Create a minimal filesystem plugin and config entry for install-path tests."""
    plugin_dir = root / entry
    plugin_dir.mkdir(parents=True)
    class_name = "".join(part.capitalize() for part in name.split("_"))
    (plugin_dir / "plugin.py").write_text(
        PLUGIN_TEMPLATE.format(
            class_name=class_name,
            name=name,
            description=f"{source} test plugin",
            topic=f"{name}.event",
            source=source,
        )
    )
    (plugin_dir / "defaults.toml").write_text(f'[defaults]\norigin = "{source}"\n')
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n'
        "native = true\n\n"
        "[[commandlets]]\n"
        f'name = "{name}"\n'
        "capabilities = []\n"
    )
    return plugin_dir


def write_signed_catalog(tmp_path: Path, root: Path, config: Path) -> tuple[Path, Path]:
    """Create a signed catalog and return (signed_catalog, public_key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    catalog = tmp_path / "catalog.json"
    signed = tmp_path / "catalog.signed.json"
    private_path = tmp_path / "catalog-signing.pem"
    public_path = tmp_path / "catalog-signing.pub.pem"
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
    write_json(catalog, build_catalog(plugin_root=root, plugin_config=config, source="local"))
    with patch("getpass.getpass", return_value="passphrase"):
        sign_catalog(catalog, private_path, "unit-test", signed)
    return signed, public_path


def write_manifest_signing_key(tmp_path: Path) -> tuple[Path, Path]:
    """Create an encrypted manifest signing keypair and return (private, public)."""
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


def sign_plugin_manifest(manifest_path: Path, private_path: Path) -> None:
    """Append a framework manifest signature block to one manifest."""
    import tomllib

    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    block = plugin_manifest_signature_block(data, private_path, passphrase="passphrase")
    lines = ["", "[bywaf_signature]"]
    for key in ("schema", "algorithm", "digest_algorithm", "digest", "value"):
        lines.append(f'{key} = "{block[key]}"')
    manifest_path.write_text(manifest_path.read_text(encoding="utf-8").rstrip() + "\n" + "\n".join(lines) + "\n")
