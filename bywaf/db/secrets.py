"""Persisted secret metadata operations for EventStore.

Provides the database-backed secret storage methods used to hydrate and persist
opaque secret references.

Used by:
- db.EventStore: inherits secret persistence behavior.
- API/app startup: reload stored secrets into the in-memory secret store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from ..secrets import SecretFingerprint, SecretRef


class EventStoreSecretMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def store_secret(self, secret_ref: SecretRef, value: str) -> None:
        """Persist a secret value in the active database."""
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
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
