# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.35

The biggest change in this release is the `Cert`/`Tsk` split.
Previously, the `Cert` class was used for both certificates (containing only public parts) and TSKs (secret keys).
The `Tsk` class was obtained through the `secrets` accessor of the `Cert`.

For better security, ergonomics, and alignment with the Stateless OpenPGP specification, this has been reversed:
  - `Tsk.from_*` functions are available for reading secret keys
  - A `Cert` can be extracted from a `Tsk` via the `extract_certificate` function

Note that all old APIs continue to work and will trigger deprecation warnings with migration suggestions.
There are no plans to remove the old APIs, and we have tests to verify that they continue to work.

In the long term, this will ensure that handing a `Cert` object to a different function will not allow it to elevate privileges and extract secret components.
Code that explicitly deals with sensitive key material in the form of `Tsk` will also be easier to spot.

`Tsk`s are, by design, quite limited in features and do not try to mimic `Cert`s.
This is a step towards a future of non-software keys, where the signer or decryptor may live in an HSM.

More details are available in the [issue comment](https://github.com/wiktor-k/pysequoia/pull/79#issuecomment-5327913731).

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
  - `Tsk.generate(validity_seconds)` defaults to `None` [#89]

Removed:
  -

[#73]: https://github.com/wiktor-k/pysequoia/pull/73
[#75]: https://github.com/wiktor-k/pysequoia/pull/75
[#77]: https://github.com/wiktor-k/pysequoia/pull/77
[#84]: https://github.com/wiktor-k/pysequoia/pull/84
[#85]: https://github.com/wiktor-k/pysequoia/pull/85
[#89]: https://github.com/wiktor-k/pysequoia/pull/89

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
