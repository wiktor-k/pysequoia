# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.37

New:

Fixed:
  - Keep GnuPG keys usable for signing after adding a User ID. [#92] [#98]

Changed:
  -

Removed:
  -

[#92]: https://github.com/wiktor-k/pysequoia/issues/92
[#98]: https://github.com/wiktor-k/pysequoia/pull/98

### Release checklist:
###  [ ] Update dependencies via `cargo upgrade --incompatible && cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
