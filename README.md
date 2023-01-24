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
import pysequoia
```

## Available functions

### encrypt

Signs and encrypts a string to one or more recipients:

```python
s = pysequoia.Cert.from_file("signing-key.asc")
r = pysequoia.Cert.from_bytes(open("wiktor.asc", "rb").read())
encrypted = pysequoia.encrypt(s, r, "content to encrypt")
print(f"Encrypted data: {encrypted}")
```

### merge

Merges data from old certificate with new packets:

```python
old = pysequoia.Cert.from_file("wiktor.asc")
new = pysequoia.Cert.from_file("wiktor-fresh.asc")
merged = pysequoia.merge(old, new)
print(f"Merged, updated cert: {merged}")
```

### minimize

Discards expired subkeys and User IDs:

```python
cert = pysequoia.Cert.from_file("wiktor.asc")
minimized = pysequoia.minimize(cert)
print(f"Minimized cert: {minimized}")
```
