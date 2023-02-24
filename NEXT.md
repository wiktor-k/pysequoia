# Next version changes
## This file contains changes that will be included in the next version that is released

New:
  - `Cert.user_ids` for retrieving a list of User IDs that the certificate has.
  - `UserId.notations` for retrieving a list of notations on a User ID.
  - `Cert.set_notations` for updating the list of notations.

Changed:

Deleted:
  - `minimize` has been removed. It was a special case function that could have surprising results.

### git tag --edit -s -F NEXT.md v...
