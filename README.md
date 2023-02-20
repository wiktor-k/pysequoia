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
from pysequoia import Cert
```

Assume this file has been generated:

```bash
gpg --batch --pinentry-mode loopback --passphrase hunter22 --quick-gen-key user@example.com
gpg --batch --pinentry-mode loopback --passphrase hunter22 --export-secret-key user@example.com > user.pgp
```

## Available functions

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("user.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
encrypted = encrypt(signer = s.signer("hunter22"), recipients = [r], content = "content to encrypt")
print(f"Encrypted data: {encrypted}")
```

### sign

Signs the data and returns armored output:

```python
from pysequoia import sign

s = Cert.from_file("signing-key.asc")
signed = sign(s.signer(), "data to be signed")
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

Note: This function is experimental and may be removed in the future.

Discards expired subkeys and User IDs:

```python
from pysequoia import minimize

cert = Cert.from_file("wiktor.asc")
minimized = minimize(cert)
print(f"Minimized cert: {minimized}")
```

### generate

Creates new general purpose key with given User ID:

```python
alice = Cert.generate("Alice <alice@example.com>")
fpr = alice.fingerprint
print(f"Generated cert with fingerprint {fpr}:\n{alice}")
```

Newly generated certificates are usable in both encryption and signing
contexts:

```python
alice = Cert.generate("Alice <alice@example.com>")
bob = Cert.generate("Bob <bob@example.com>")

encrypted = encrypt(signer = alice.signer(), recipients = [bob], content = "content to encrypt")
print(f"Encrypted data: {encrypted}")
```

### WKD

Fetching certificates via Web Key Directory:

```python
from pysequoia import WKD
import asyncio

async def fetch_and_display():
    cert = await WKD.search(email = "test-wkd@metacode.biz")
    print(f"Cert found via WKD: {cert}")
    assert cert.fingerprint == "5b7abe660d5c62a607fe2448716b17764e3fcaca"

asyncio.run(fetch_and_display())
```

### Key server

Fetching certificates via HKPS protocol:

```python
from pysequoia import KeyServer
import asyncio

async def fetch_and_display():
    ks = KeyServer("hkps://keys.openpgp.org")
    cert = await ks.get("653909a2f0e37c106f5faf546c8857e0d8e8f074")
    print(f"Cert found via HKPS: {cert}")
    assert cert.fingerprint == "653909a2f0e37c106f5faf546c8857e0d8e8f074"

asyncio.run(fetch_and_display())
```

### CertD integration

The library exposes [OpenPGP Certificate Directory][CERT-D]
integration which allows storing and retrieving OpenPGP certificates
in a persistent way directly in the file system.

Note that this will *not* allow you to read GnuPG-specific key
directories. Cert-D [does not allow certificate removal][NO-REMOV].

[CERT-D]: https://sequoia-pgp.gitlab.io/pgp-cert-d/
[NO-REMOV]: https://gitlab.com/sequoia-pgp/pgp-cert-d/-/issues/33

```python
from pysequoia import Store

cert = Cert.from_file("wiktor.asc")
s = Store("/tmp/store")
s.put(cert)
assert s.get(cert.fingerprint) != None
```

The certificate is now stored in the given directory and can be
retrieved later by its fingerprint:

```python
s = Store("/tmp/store")
assert s.get("653909a2f0e37c106f5faf546c8857e0d8e8f074") != None
```

### OpenPGP Cards

There's an experimental feature allowing communication with OpenPGP
Cards (like Yubikey or Nitrokey).

```py
from pysequoia import Card

# enumerate all cards
all = Card.all()

# open card by card ident
card = Card.open("card ident")

print(card.ident)
print(card.cardholder)

signer = card.signer(input("PIN: "))

signed = sign(signer, "data to be signed")
```
