# PySequoia

[![PyPI version](https://badge.fury.io/py/pysequoia.svg)](https://pypi.org/project/pysequoia/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/pysequoia.svg?label=PyPI%20downloads)](
https://pypi.org/project/pysequoia/)
[![status-badge](https://ci.codeberg.org/api/badges/wiktor/pysequoia/status.svg)](https://ci.codeberg.org/wiktor/pysequoia)

Provides [OpenPGP][] facilities in Python through [Sequoia PGP][SQ] library. If
you need to work with encryption and digital signatures using IETF
standard this package is for you!

[OpenPGP]: https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP
[SQ]: https://sequoia-pgp.org/

Note: This is a work in progress. The API is **not** stable!

## Building

```bash
set -euxo pipefail
python3 -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
```

## Installing

PySequoia can be installed through `pip`:

```sh
pip install pysequoia
```

## Testing

This entire document is used for end-to-end, integration tests that
exercise package's API surface.

Tests assume these keys and cards exist:

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

All examples assume these basic classes have been imported:

```python
from pysequoia import Cert
```

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("passwd.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
encrypted = encrypt(signer = s.signer("hunter22"), recipients = [r], content = "content to encrypt")
print(f"Encrypted data: {encrypted}")
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

### sign

Signs the data and returns armored output:

```python
from pysequoia import sign

s = Cert.from_file("signing-key.asc")
signed = sign(s.signer(), "data to be signed")
print(f"Signed data: {signed}")
```

### Certificates API

The `Cert` class represents one OpenPGP certificate (commonly called a
"public key").

This package additionally verifies the certificate using Sequoia PGP's
[`StandardPolicy`][SP]. This means that certificates using weak
cryptography can fail to load or present different view than the one
in other OpenPGP software (e.g. if the User ID uses SHA-1 in
back-signatures it may be missing from the list returned by this
package).

[SP]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/struct.StandardPolicy.html

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

#### merge

Merges data from old certificate with new packets:

```python
old = Cert.from_file("wiktor.asc")
new = Cert.from_file("wiktor-fresh.asc")
merged = old.merge(new)
print(f"Merged, updated cert: {merged}")
```

#### User IDs

```python
cert = Cert.from_file("wiktor.asc")
user_id = cert.user_ids[0]
assert str(user_id).startswith("Wiktor Kwapisiewicz")
```

#### Notations

Notations are small pieces of data that can be attached to signatures (and, indirectly, to User IDs).

The following example reads and displays [Keyoxide][KX] proof URI:

[KX]: https://keyoxide.org/

```python
cert = Cert.from_file("wiktor.asc")
user_id = cert.user_ids[0]
notation = user_id.notations[0]

assert notation.key == "proof@metacode.biz";
assert notation.value == "dns:metacode.biz?type=TXT";
```

Notations can also be added:

```python
from pysequoia import Notation

cert = Cert.from_file("signing-key.asc")

# No notations initially
assert len(cert.user_ids[0].notations) == 0;

cert = cert.set_notations(cert.signer(), [Notation("proof@metacode.biz", "dns:metacode.biz")])

# Has one notation now
print(str(cert.user_ids[0].notations))
assert len(cert.user_ids[0].notations) == 1;

# Check the notation data
notation = cert.user_ids[0].notations[0]

assert notation.key == "proof@metacode.biz";
assert notation.value == "dns:metacode.biz";
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

## License

This project is licensed under [Apache License, Version 2.0][APL].

[APL]: https://www.apache.org/licenses/LICENSE-2.0.htmlq

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the package by you shall be under the terms
and conditions of this license, without any additional terms or
conditions.

## Sponsors

My work is being supported by these generous organizations
(alphabetical order):
  - [nlnet.nl](https://nlnet.nl/)
  - [pep.foundation](https://pep.foundation/)
  - [sovereigntechfund.de](https://sovereigntechfund.de/en.html)
