# PySequoia

Note: This is a work in progress. The API is **not** stable!

Building:

```bash
set -euxo pipefail
python3 -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
```

Now open the console with `python`{.verbatim} and import the library:

```python
import pysequoia
```

## Available functions

### encrypt

Signs and encrypts a string to one or more recipients:

```python
s = open("signing-key.asc", "r").read()
r = open("wiktor.asc", "r").read()
pysequoia.encrypt(s, r, "content to encrypt")
```

### merge

Merges data from old certificate with new packets:

```python
old = open("wiktor.asc", "r").read()
new = open("wiktor-fresh.asc", "r").read()
pysequoia.merge(old, new)
```

### minimize

Discards expired subkeys and User IDs:

```python
cert = open("wiktor.asc", "r").read()
pysequoia.minimize(cert)
```
