# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.36

New:
  - Add configurable cryptographic policies, including system Sequoia policy profiles and legacy SHA-1 signature verification.
  - Allow selecting the hash algorithm when signing data or files.

Fixed:
  -

Changed:
  -

Removed:
  -

[#73]: https://github.com/wiktor-k/pysequoia/pull/73
[#75]: https://github.com/wiktor-k/pysequoia/pull/75
[#77]: https://github.com/wiktor-k/pysequoia/pull/77
[#84]: https://github.com/wiktor-k/pysequoia/pull/84
[#85]: https://github.com/wiktor-k/pysequoia/pull/85
[#89]: https://github.com/wiktor-k/pysequoia/pull/89

### Release checklist:
###  [ ] Update dependencies via `cargo upgrade --incompatible && cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
