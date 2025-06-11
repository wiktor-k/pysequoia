# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.29

New:
  - `Cert.generate` has a new `profile` parameter. The default is `Profile.RFC4880` which generates widely compatible certificates. The new option - `Profile.RFC9580` - generates newer, v6 certificates. Thanks to @jap for the contribution! [#47]

Changed:

Removed:

[#47]: https://github.com/wiktor-k/pysequoia/pull/47
### git tag --edit -s -F NEXT.md v...
