# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.32

New:
  - `Cert.secrets` is now typed as `Tsk` instead of `Any`
  - `Tsk` now supports `__bytes__` and `__repr__` [#73]

Changed:
  - `Cert.generate` has a new option to control expiration: `validity_seconds` [#75]

Removed:
  - 

[#73]: https://github.com/wiktor-k/pysequoia/pull/73
[#75]: https://github.com/wiktor-k/pysequoia/pull/75

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
