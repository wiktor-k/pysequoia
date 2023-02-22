# PySequoia

[![PyPI version](https://badge.fury.io/py/pysequoia.svg)](https://pypi.org/project/pysequoia/)

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

Assuming these keys and cards exist:

```bash
# generate a key with password
gpg --batch --pinentry-mode loopback --passphrase hunter22 --quick-gen-key passwd@example.com
gpg --batch --pinentry-mode loopback --passphrase hunter22 --export-secret-key passwd@example.com > passwd.pgp

# generate a key without password
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key no-passwd@example.com future-default
gpg --batch --pinentry-mode loopback --passphrase '' --export-secret-key no-passwd@example.com > no-passwd.pgp

# initialize dummy OpenPGP Card
sh /start.sh
echo 12345678 > pin
/root/.cargo/bin/opgpcard admin --card 0000:00000000 --admin-pin pin import no-passwd.pgp
```

## Available functions

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("passwd.pgp")
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
print(f"Signed data: {signed}")
```

### decrypt

Decrypts data:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.signer(), recipients = [receiver], content = content)

print(f"Encrypted data: {encrypted}")

decrypted = decrypt(decryptor = receiver.decryptor("hunter22"), data = encrypted)

assert content == decrypted.content;
```

### Certificates API

The `Cert` class exposes the following functions.

#### merge

Merges data from old certificate with new packets:

```python
old = Cert.from_file("wiktor.asc")
new = Cert.from_file("wiktor-fresh.asc")
merged = old.merge(new)
print(f"Merged, updated cert: {merged}")
```

#### generate

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

## Certificate management

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

## OpenPGP Cards

There's an experimental feature allowing communication with OpenPGP
Cards (like Yubikey or Nitrokey).

```python
from pysequoia import Card

# enumerate all cards
all = Card.all()

# open card by card ident
card = Card.open("0000:00000000")

print(f"Card ident: {card.ident}")
print(f"Cardholder: {card.cardholder}")
```

Cards can be used for signing data:

```python
signer = card.signer("123456")

signed = sign(signer, "data to be signed")
print(f"Signed data: {signed}")
```

As well as for decryption:

```python
decryptor = card.decryptor("123456")

sender = Cert.from_file("passwd.pgp")
receiver = Cert.from_file("no-passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.signer("hunter22"), recipients = [receiver], content = content)

print(f"Encrypted data: {encrypted}")

decrypted = decrypt(decryptor = decryptor, data = encrypted)

assert content == decrypted.content;
```

Note that while this package allows using cards for signing and
decryption the provisioning process is not supported.
[OpenPGP card tools][] can be used to initialize the card.

[OpenPGP card tools]: https://crates.io/crates/openpgp-card-tools

## Sponsors

My work is being supported by these generous organizations
(alphabetical order):
  - [nlnet.nl](https://nlnet.nl/)
  - [pep.foundation](https://pep.foundation/)
  - [sovereigntechfund.de](https://sovereigntechfund.de/)
