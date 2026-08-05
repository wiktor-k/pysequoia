# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.33

New:
  - `Tsk` now supports `__bytes__` and `__repr__` [#73]
  - `verify` now supports compressed signatures [#77]
  - `Cert.generate` has a new option to control expiration: `validity_seconds` [#75]
  - `Packet` now supports `__bytes__` to get the full serialized packet [#85]
  - Post-quantum cryptography (PQC) support via sequoia-openpgp 2.4:
    - `PublicKeyAlgorithm` now includes PQC variants (ML-DSA, SLH-DSA, ML-KEM)
    - New `CipherSuite` enum for `Tsk.generate()` with PQC presets (`MLDSA65_Ed25519`, `MLDSA87_Ed448`)
    - New `SigningAlgorithm` and `EncryptionAlgorithm` enums for fine-grained algorithm selection (e.g. SLH-DSA signing with classical encryption)

Fixed:
  - `Packet.body` now returns just the body bytes without the tag and length header [#85]

Changed:
  -

Removed:
  -

[#73]: https://github.com/wiktor-k/pysequoia/pull/73
[#75]: https://github.com/wiktor-k/pysequoia/pull/75
[#77]: https://github.com/wiktor-k/pysequoia/pull/77
[#84]: https://github.com/wiktor-k/pysequoia/pull/84
[#85]: https://github.com/wiktor-k/pysequoia/pull/85

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
