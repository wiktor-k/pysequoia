# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.24

New:
  - `Sig` - new class exposing signature related functions:
  - `Sig.from_file` - read detached signature from file,
  - `Sig.from_bytes` - read detached signature from bytes,
  - `sig.issuer_fpr` - fingerprint of the issuer (may be `None`),
  - `sig.created` - date and time when the signature was issued,

Changed:

Removed:

### git tag --edit -s -F NEXT.md v...
