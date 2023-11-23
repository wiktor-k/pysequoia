# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.21

New:
  - `Card.cert_url` - for retrieving certificate URL stored on the card, note that the URL returned can be empty or invalid,
  - `Card.keys` - for enumerating secret keys stored on the card,

Changed:

Removed:
  - `WKD`, `KeyServer` - networking features that depended on `sequoia_net` have been removed to reduce the dependency footprint,
### git tag --edit -s -F NEXT.md v...
