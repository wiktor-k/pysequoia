# Next version changes
## This file contains changes that will be included in the next version that is released
v0.1.17

New:
  - `Cert.expiration` for getting key expiration time ([#27]).
  - `Cert.set_expiration` for setting key expiration time ([#27]).

Changed:
  - `sign` takes a bytes argument named `bytes` now instead of `data` string [#22].
  - `encrypt` takes a bytes argument named `bytes` now instead of `content` string and returns bytes instead of string [#22].
  - `decrypt` takes a bytes argument named `bytes` now instead of `data` string argument [#22].
  - the structure returned by `decrypt` has now a `bytes` getter and it returns bytes object instead of a string [#22].

Removed:

[#22]: https://codeberg.org/wiktor/pysequoia/issues/22
[#27]: https://codeberg.org/wiktor/pysequoia/issues/27
### git tag --edit -s -F NEXT.md v...
