# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.31

New:

Changed:
  - This release changes metadata of the project and the release workflow. There are no functional changes. See changelog for version 0.1.30.
  - Changed Rust edition from 2021 to 2024.

Removed:

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
