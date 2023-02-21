# Next version changes
## This file contains changes that will be included in the next version that is released

New:
  - `Cert.signer()` now accepts a password argument for password protected files.

Changed:
  - `Cert` objects are now always viewed through Sequoia's `StandardPolicy`. This makes it filter out weak algorithms.
  - `encrypt` supports multiple recipients.
  - `Card` usage examples are now tested in CI.
  - `sequoia_openpgp` now uses CNG on Windows and Nettle otherwise.

Deleted:
  - `Context` object removed since now each `Cert` object contains its own policy.

### git tag --edit -s -F NEXT.md v...
