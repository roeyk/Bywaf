# Key Management

This document records Bywaf's maintainer policy for official plugin manifest
signing keys and public verification keys.

## Document Index

- [Key Types](#key-types)
- [Private Key Storage Controls](#private-key-storage-controls)
- [Public Key Storage Controls](#public-key-storage-controls)
- [Rotation Policy](#rotation-policy)
- [Emergency Revocation](#emergency-revocation)

## Key Types

Private manifest-signing keys are maintainer secrets. They are used only by
maintainer signing tooling, such as `scripts/plugin_manifest_sign.py`, to sign
official plugin manifests before release.

Public manifest verification keys are distributable trust anchors. They can be
committed, packaged, and listed in release notes so operators can verify which
official key signed a manifest.

## Private Key Storage Controls

Private manifest-signing keys must:

- stay outside the repository and outside the `bywaf/` package tree;
- never be committed, packaged, emailed, pasted into issues, or written into
  documentation;
- be encrypted at rest;
- use file permissions no broader than `0600` on maintainer-controlled
  systems;
- be owned only by the maintainer account or release automation account that
  performs signing;
- use a passphrase stored separately from the private key, such as in a
  password manager or CI secret store;
- be backed up only as encrypted material;
- be used only by maintainer signing tools, never by the Bywaf interpreter.

Passphrases must not be committed, printed in logs, or stored in shell history.
When release automation supplies a passphrase through an environment variable,
the variable must come from the CI secret store and be scoped to the signing
job.

## Public Key Storage Controls

Official public verification keys live under `bywaf/keys/` when they are
published with a release. Each public key should have a stable key id or
fingerprint, and release notes should identify the active signing key
fingerprint used for official plugin manifests.

`bywaf/keys/plugin-manifest.pub.pem.example` is a placeholder, not a public key.
It documents the planned package location without committing real trust
material.

Operators can use `--plugin-manifest-key` to trust a local or third-party
public key outside the official Bywaf key set.

## Rotation Policy

Official manifest-signing keys rotate annually with a 60-day staggered
transition:

- publish the next public verification key before it is used for signing;
- temporarily trust both the current and next public keys during the 60-day
  transition window;
- start signing new manifests with the next private key on the rotation date;
- re-sign official plugin manifests with the next private key and release those
  updated manifests with the rotation release;
- retire the old public key after the transition window.

Retired keys are no longer part of the official trusted key set for normal
annual rotation.

## Emergency Revocation

Revocation is reserved for suspected compromise or emergency distrust. A
revoked key is removed from the official trusted key set immediately, without
waiting for the normal 60-day retirement window.

An emergency revocation release should:

- remove trust for the affected public key;
- publish or confirm the replacement public key;
- re-sign official plugin manifests with an uncompromised private key;
- identify the revoked key fingerprint in the release notes.

Runtime multi-key verification, key retirement metadata, and emergency
revocation metadata are deferred until Bywaf ships real official public keys.
