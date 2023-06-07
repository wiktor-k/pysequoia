# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.20

New:
  - `KeyServer.search` for looking up keys using e-mail addresses ([#77]).
  - `Cert.secrets` for retrieving secret keys from a certificate ([#81]).
  - `Cert.has_secret_keys` for checking if certificate contains secret keys ([#81]).
  - `Cert.bytes` for returning raw Certificate bytes ([#85]).
  - `Cert.is_revoked` for checking potential revocation status ([#83]).
  - `Cert.revoke` for creating certificate revocation signatures ([#83]).
  - `Cert.split_bytes` for parsing multiple certificates from keyring bytes ([#88]).
  - `Cert.split_file` for parsing multiple certificates from keyring file ([#88]).
  - `Cert.generate` now accepts a list of User IDs as the `user_ids` keyword argument ([#82]).

Changed:
  - `WKD.search` now returns a list of certificates ([#76]).
  - `Cert.signer` moved to `Cert.secrets.signer` since it requires secret key material ([#81]).
  - `Cert.decryptor` moved to `Cert.secrets.decryptor` since it requires secret key material ([#81]).
  - `Cert.revoke_user_id` returns a revocation signature now instead of Cert with revoked User ID.

Removed:

[#76]: https://codeberg.org/wiktor/pysequoia/issues/76
[#77]: https://codeberg.org/wiktor/pysequoia/issues/77
[#81]: https://codeberg.org/wiktor/pysequoia/issues/81
[#82]: https://codeberg.org/wiktor/pysequoia/issues/82
[#83]: https://codeberg.org/wiktor/pysequoia/issues/83
[#85]: https://codeberg.org/wiktor/pysequoia/issues/85
[#88]: https://codeberg.org/wiktor/pysequoia/issues/88

### git tag --edit -s -F NEXT.md v...
