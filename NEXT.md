# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.30

New:
  - `Cert.generate` has a new `profile` parameter. The default is `Profile.RFC4880` which generates widely compatible certificates. The new option - `Profile.RFC9580` - generates newer, v6 certificates. Thanks to @jap for the contribution! [#47]
  - `encrypt_file` and `decrypt_file` added for handling bigger files. Thanks to @dnet for the contribution! [#53]
  - `encrypt`, `encrypt_file`, `decrypt` and `decrypt_file` can use symmetric encryption via the `passwords` argument [#55]
  - stub files available for PySequoia types [#51]

Changed:
  - Changed Rust edition from 2021 to 2024.

Removed:

[#47]: https://github.com/wiktor-k/pysequoia/pull/47
[#51]: https://github.com/wiktor-k/pysequoia/pull/51
[#53]: https://github.com/wiktor-k/pysequoia/pull/53
[#55]: https://github.com/wiktor-k/pysequoia/pull/55

### Release checklist:
###  [ ] Change version in `Cargo.toml` and `pyproject.toml` and `NEXT.md`
###  [ ] Update dependencies via `cargo update`
###  [ ] Regenerate stubs with `just update-stubs`
###  [ ] Commit and push, wait for CI, merge
###  [ ] `git pull`, tag locally with `git tag --edit -s -F NEXT.md v...` and `git push`
