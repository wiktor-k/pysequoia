# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.28

New:
  - `verify` can be used to verify detached signatures through the new `signature` keyword parameter([#42])
  - `verify` accepts a `file` parameter for direct verification of files

Changed:
  - `Sig.bytes()` is now `Sig.__bytes__()` to align with idiomatic Python. Convert all instances of `sig.bytes()` to `bytes(sig)` which automatically calls the magic function.
  - `Cert.bytes()` is now `Cert.__bytes__()` to align with idiomatic Python. Convert all instances of `cert.bytes()` to `bytes(cert)` which automatically calls the magic function.

Removed:

[#42]: https://github.com/wiktor-k/pysequoia/issues/42
### git tag --edit -s -F NEXT.md v...
