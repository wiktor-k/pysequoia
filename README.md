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

Now open the console with `python` and import the library:

```python
from pysequoia import Cert, Context
```

## Available functions

### encrypt

Signs and encrypts a string to one or more recipients:

```python
s = Cert.from_file("signing-key.asc")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
encrypted = Context.standard().encrypt(s, r, "content to encrypt")
print(f"Encrypted data: {encrypted}")
```

### merge

Merges data from old certificate with new packets:

```python
old = Cert.from_file("wiktor.asc")
new = Cert.from_file("wiktor-fresh.asc")
merged = old.merge(new)
print(f"Merged, updated cert: {merged}")
```

### minimize

Discards expired subkeys and User IDs:

```python
cert = Cert.from_file("wiktor.asc")
minimized = Context.standard().minimize(cert)
print(f"Minimized cert: {minimized}")
```
