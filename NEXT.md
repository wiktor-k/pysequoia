# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.31

New:
  - Added `Sig.issuer_fingerprint`, `Sig.issuer_key_id`, `Sig.signers_user_id`, and `Sig.expiration` [#60]
  - Added docstrings to the `Sig` API [#60]
  - Added `PacketPile` and `Packet` for low-level reading of individual packet fields [#61]
  - Added `Sig.signature_type`, `Sig.hash_algorithm`, `Sig.key_algorithm`, and `Sig.key_validity_period` [#61]
  - Added `SignatureType`, `PublicKeyAlgorithm`, `HashAlgorithm`, `DataFormat`, `Tag` and `KeyFlags` as returned types [#61]

Changed:
  - `Sig.issuer_fpr` is now considered deprecated, use `Sig.issuer_fingerprint` instead [#60]

Removed:

[#60]: https://github.com/wiktor-k/pysequoia/pull/60
[#61]: https://github.com/wiktor-k/pysequoia/pull/61

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
