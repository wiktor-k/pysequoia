# Next version changes
## This file contains changes that will be included in the next version that is released
v

New:
  - `KeyServer.put` for uploading keys to keyservers.
  - `KeyServer.get` supports `vks` protocol now.
  - `KeyServer.put` supports `vks` protocol now.
  - `Cert.certifier` for getting key usable for certifications.
  - `Cert.add_user_id` for appending User IDs to certificates.
  - `Cert.revoke_user_id` for revoking previously added User IDs.

Changed:
  - `Cert.user_ids` will return only non-revoked User IDs.

Removed:

### git tag --edit -s -F NEXT.md v...
