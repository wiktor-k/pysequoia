# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.20

New:
  - `KeyServer.search` for looking up keys using e-mail addresses ([#77]).
  - `Cert.secrets` for retrieving secret keys from a certificate ([#81]).
  - `Cert.has_secret_keys` for checking if certificate contains secret keys ([#81]).

Changed:
  - `WKD.search` now returns a list of certificates ([#76]).

Removed:

[#76]: https://codeberg.org/wiktor/pysequoia/issues/76
[#77]: https://codeberg.org/wiktor/pysequoia/issues/77
[#81]: https://codeberg.org/wiktor/pysequoia/issues/81

### git tag --edit -s -F NEXT.md v...
