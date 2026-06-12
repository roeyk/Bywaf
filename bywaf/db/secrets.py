"""Persisted secret metadata operations for EventStore.

Provides the database-backed secret storage methods used to hydrate and persist
opaque secret references.

Used by:
- db.EventStore: inherits secret persistence behavior.
- API/app startup: reload stored secrets into the in-memory secret store."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from ..time_format import bywaf_now_iso
from .backends import DatabaseConnection
from ..secret.store import SecretFingerprint, SecretRef


class EventStoreSecretMixin:
    """Adds persisted secret-reference methods to `EventStore`.

    Constructed by: multiple inheritance in `db.EventStore`.
    Used by: app/API startup hydration and secret-aware command execution.
    """

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def store_secret(self, secret_ref: SecretRef, value: str) -> None:
        """Persist a secret value in the active database."""
        now = bywaf_now_iso()
        with self.connect() as conn:
            # Secret refs are stable handles; updates replace the encrypted or
            # plaintext backing value while preserving the user-facing ref.
            conn.execute(
                """
                INSERT INTO secrets(ref, name, value, fingerprint, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ref) DO UPDATE SET
                    name = excluded.name,
                    value = excluded.value,
                    fingerprint = excluded.fingerprint,
                    source = excluded.source,
                    updated_at = excluded.updated_at
                """,
                (
                    secret_ref.ref,
                    secret_ref.name,
                    value,
                    secret_ref.fingerprint.format(),
                    secret_ref.source,
                    now,
                    now,
                ),
            )

    def stored_secrets(self) -> list[tuple[SecretRef, str]]:
        """Return persisted secrets for hydrating the in-memory secret store."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ref, name, value, fingerprint, source FROM secrets ORDER BY name, ref"
            ).fetchall()
        secrets: list[tuple[SecretRef, str]] = []
        for row in rows:
            algorithm, _, digest = str(row["fingerprint"]).partition(":")
            # The in-memory SecretStore wants SecretRef metadata plus the raw
            # value. Rehydrate both so command execution can resolve refs.
            secrets.append(
                (
                    SecretRef(
                        ref=str(row["ref"]),
                        name=str(row["name"]),
                        fingerprint=SecretFingerprint(algorithm or "unknown", digest),
                        source=str(row["source"]),
                    ),
                    str(row["value"]),
                )
            )
        return secrets
