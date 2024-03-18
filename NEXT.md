# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.23

New:
  - `decrypt` accepts a function for supplying certificates for signature verification ([#22])
  - the result of `decrypt` and `verify` exposes `valid_sigs` for retrieving a list of valid signatures ([#22])

Changed:
  - `verify` accepts a callback for supplying signing certificates ([#20])
  - `encrypt` does not require the `signer` argument ([#22])

Removed:
  - `Store` and the Cert-D has been removed ([#20]) due to confusing semantics

[#20]: https://github.com/wiktor-k/pysequoia/pull/20
[#22]: https://github.com/wiktor-k/pysequoia/pull/22
### git tag --edit -s -F NEXT.md v...
