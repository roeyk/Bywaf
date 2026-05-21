# Bywaf Verification Keys

This package is reserved for public verification keys distributed with official
Bywaf releases.

Only public verification keys belong here. Private manifest-signing keys are
maintainer release material and must stay outside the repository and built
packages.

`plugin-manifest.pub.pem` is the planned public-key filename for official
plugin manifest signatures. Operators can still use `--plugin-manifest-key` to
trust a different public key for local or third-party plugin ecosystems.

Maintainer policy is to rotate official manifest-signing keys annually with a
60-day staggered transition:

- Publish the next public verification key before it is used for signing.
- Temporarily trust both the current and next public keys during the transition
  window.
- Start signing new manifests with the next private key on the rotation date.
- Re-sign official plugin manifests with the next private key and release those
  updated manifests with the rotation release.
- Retire the old public key after the 60-day transition window.

Retired keys are no longer part of the official trusted key set for normal
annual rotation. Revocation is reserved for suspected compromise or emergency
distrust and removes the affected key from trust immediately. Private signing
keys stay outside the repository and built packages throughout the key
lifecycle.
