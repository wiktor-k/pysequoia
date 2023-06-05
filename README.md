<img src="https://codeberg.org/wiktor/pysequoia/raw/branch/main/doc/logo.png" align="right" width="150" height="150" />

# PySequoia

[![PyPI version](https://badge.fury.io/py/pysequoia.svg)](https://pypi.org/project/pysequoia/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/pysequoia.svg?label=PyPI%20downloads)](
https://pypi.org/project/pysequoia/)
[![status-badge](https://ci.codeberg.org/api/badges/wiktor/pysequoia/status.svg)](https://ci.codeberg.org/wiktor/pysequoia)

This library provides [OpenPGP][] facilities in Python through the
[Sequoia PGP][SQ] library. If you need to work with encryption and
digital signatures using an [IETF standardized protocol][4880], this
package is for you!

[OpenPGP]: https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP
[SQ]: https://sequoia-pgp.org/
[4880]: https://www.rfc-editor.org/rfc/rfc4880

Note: This is a work in progress. The API is **not** stable!

## Building

```bash
set -euxo pipefail
python -m venv .env
source .env/bin/activate
pip install maturin
maturin develop
```

## Installing

PySequoia can be installed through `pip`:

```sh
pip install pysequoia
```

Note that since `pysequoia` is implemented largely in Rust, a [Rust
toolchain][RUSTUP] is necessary for the installation to succeed.

[RUSTUP]: https://rustup.rs/

## Testing

This entire document is used for end-to-end integration tests that
exercise the package's API surface.

The tests assume that these keys and cards exist:

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
opgpcard admin --card 0000:00000000 --admin-pin pin import no-passwd.pgp
```

## Functions

All examples assume that these basic classes have been imported:

```python
from pysequoia import Cert
```

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("passwd.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
bytes = "content to encrypt".encode("utf8")
encrypted = encrypt(signer = s.secrets().signer("hunter22"), recipients = [r], bytes = bytes).decode("utf8")
print(f"Encrypted data: {encrypted}")
```

### decrypt

Decrypts data:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.secrets().signer(), recipients = [receiver], bytes = content.encode("utf8"))

decrypted = decrypt(decryptor = receiver.secrets().decryptor("hunter22"), bytes = encrypted)

assert content == decrypted.bytes.decode("utf8");
```

### sign

Signs data and returns armored output:

```python
from pysequoia import sign

s = Cert.from_file("signing-key.asc")
signed = sign(s.secrets().signer(), "data to be signed".encode("utf8"))
print(f"Signed data: {signed}")
```

## Certificates

The `Cert` class represents one OpenPGP certificate (commonly called a
"public key").

This package additionally verifies the certificate using Sequoia PGP's
[`StandardPolicy`][SP]. This means that certificates using weak
cryptography can fail to load, or present a different view than in
other OpenPGP software (e.g. if a User ID uses SHA-1 in its
back-signature, it may be missing from the list of User IDs returned
by this package).

Checking certificates for problems ("linting") [is planned][LINT] but
not yet implemented.

[SP]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/struct.StandardPolicy.html
[LINT]: https://codeberg.org/wiktor/pysequoia/issues/52

Certificates have two forms, one is ASCII armored and one is raw bytes:

```python
cert = Cert.generate("Test <test@example.com>")

print(f"Armored cert: {cert}")
print(f"Bytes of the cert: {cert.bytes()}")
```

### generate

Creates a new general purpose key with a given User ID:

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

bytes = "content to encrypt".encode("utf8")

encrypted = encrypt(signer = alice.secrets().signer(), recipients = [bob], bytes = bytes)
print(f"Encrypted data: {encrypted}")
```

### merge

Merges packets from a new version into an old version of a certificate:

```python
old = Cert.from_file("wiktor.asc")
new = Cert.from_file("wiktor-fresh.asc")
merged = old.merge(new)
print(f"Merged, updated cert: {merged}")
```

### User IDs

Listing existing User IDs:

```python
cert = Cert.from_file("wiktor.asc")
user_id = cert.user_ids[0]
assert str(user_id).startswith("Wiktor Kwapisiewicz")
```

Adding new User IDs:

```python
cert = Cert.generate("Alice <alice@example.com>")
assert len(cert.user_ids) == 1;

cert = cert.add_user_id(value = "Alice <alice@company.invalid>", certifier = cert.secrets().certifier())

assert len(cert.user_ids) == 2;
```

Revoking User IDs:

```python
cert = Cert.generate("Bob <bob@example.com>")

cert = cert.add_user_id(value = "Bob <bob@company.invalid>", certifier = cert.secrets().certifier())
assert len(cert.user_ids) == 2;

cert = cert.revoke_user_id(user_id = cert.user_ids[1], certifier = cert.secrets().certifier())
print(str(cert.user_ids))
assert len(cert.user_ids) == 1;
```

### Notations

Notations are small pieces of data that can be attached to signatures (and, indirectly, to User IDs).

The following example reads and displays a [Keyoxide][KX] proof URI:

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

cert = cert.set_notations(cert.secrets().certifier(), [Notation("proof@metacode.biz", "dns:metacode.biz")])

# Has one notation now
print(str(cert.user_ids[0].notations))
assert len(cert.user_ids[0].notations) == 1;

# Check the notation data
notation = cert.user_ids[0].notations[0]

assert notation.key == "proof@metacode.biz";
assert notation.value == "dns:metacode.biz";
```

### Key expiration

Certs have an `expiration` getter for retrieving the current key
expiry time:

```python
cert = Cert.from_file("signing-key.asc")

# Cert does not have any expiration date:
assert cert.expiration is None

cert = Cert.from_file("wiktor.asc")
# Cert expires on New Year's Eve
assert str(cert.expiration) == "2022-12-31 12:00:02+00:00"
```

Key expiration can also be adjusted with `set_expiration`:

```python
from datetime import datetime

cert = Cert.from_file("signing-key.asc")

# Cert does not have any expiration date:
assert cert.expiration is None

# Set the expiration to some specified point in time
expiration = datetime.fromisoformat("2021-11-04T00:05:23+00:00")
cert = cert.set_expiration(expiration = expiration, certifier = cert.secrets().certifier())
assert str(cert.expiration) == "2021-11-04 00:05:23+00:00"
```

## Secret keys

Certificates generated through `Cert.generate()` contain secret keys
and can be used for signing and decryption.

To avoid accidental leakage secret keys are never directly printed
when the Cert is written to a string. To enable this behavior use
`Cert.secrets()`. `secrets()` returns `None` on certificates which do
not contain any secret key material.

```python
c = Cert.generate("Testing key <test@example.com>")
assert c.has_secret_keys

# by default only public parts are exported
public_parts = Cert.from_bytes(f"{c}".encode("utf8"))
assert not public_parts.has_secret_keys
assert public_parts.secrets() is None

# to export secret parts use the following:
private_parts = Cert.from_bytes(f"{c.secrets()}".encode("utf8"))
assert private_parts.has_secret_keys
```

## Certificate management

### WKD

Fetching certificates via Web Key Directory:

```python
from pysequoia import WKD
import asyncio

async def fetch_and_display():
    certs = await WKD.search(email = "test-wkd@metacode.biz")
    assert len(certs) == 1
    print(f"Cert found via WKD: {certs[0]}")
    assert certs[0].fingerprint == "5b7abe660d5c62a607fe2448716b17764e3fcaca"

asyncio.run(fetch_and_display())
```

### Key server

Key servers let people search and store OpenPGP certificates.

#### HKPS

[HKPS][HKP] is a popular protocol implemented by most key servers.

[HKP]: https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00

Fetching certificates via the HKPS protocol:

```python
from pysequoia import KeyServer
import asyncio

async def fetch_and_display():
    ks = KeyServer("hkps://keyserver.ubuntu.com")
    cert = await ks.get("653909a2f0e37c106f5faf546c8857e0d8e8f074")
    print(f"Cert found via HKPS: {cert}")
    assert cert.fingerprint == "653909a2f0e37c106f5faf546c8857e0d8e8f074"

asyncio.run(fetch_and_display())
```

Search by e-mail returns multiple certificates:

```python
from pysequoia import KeyServer
import asyncio
from uuid import uuid4

async def fetch_and_display():
    ks = KeyServer("hkps://keyserver.ubuntu.com")
    certs = await ks.search(email = f"{uuid4()}@metacode.biz")
    print(f"Found {len(certs)} via HKPS: {certs}")
    assert len(certs) == 0

asyncio.run(fetch_and_display())
```

Keys can also be uploaded:

```python
from pysequoia import KeyServer
import asyncio

async def upload_key(cert):
    ks = KeyServer("hkps://keyserver.ubuntu.com")
    await ks.put(cert)
    print("Cert uploaded successfully")

asyncio.run(upload_key(Cert.from_file("wiktor.asc")))
```

#### VKS

[Verifying Key Server protocol][VKS] is a custom protocol currently
only used by the keys.openpgp.org key server. Keys retrieved via this
protocol will contain only User IDs that have been verified (via
e-mail) by the server operator.

[VKS]: https://keys.openpgp.org/about/api

```python
from pysequoia import KeyServer
import asyncio

async def fetch_and_display():
    ks = KeyServer("vks://keys.openpgp.org")
    cert = await ks.get("653909a2f0e37c106f5faf546c8857e0d8e8f074")
    print(f"Cert found via HKPS: {cert}")
    assert cert.fingerprint == "653909a2f0e37c106f5faf546c8857e0d8e8f074"

asyncio.run(fetch_and_display())
```

Search by e-mail always returns zero or one certificates via the VKS
protocol but to keep the interface consistent with HKPS the return
value is a list:

```python
from pysequoia import KeyServer
import asyncio
from uuid import uuid4

async def fetch_and_display():
    ks = KeyServer("vks://keys.openpgp.org")
    certs = await ks.search(email = "test-wkd@metacode.biz")
    print(f"Found {len(certs)} via HKPS: {certs}")
    assert len(certs) == 1

asyncio.run(fetch_and_display())
```

Keys can also be uploaded:

```python
from pysequoia import KeyServer
import asyncio

async def upload_key(cert):
    ks = KeyServer("vks://keys.openpgp.org")
    await ks.put(cert)
    print("Cert uploaded successfully")

asyncio.run(upload_key(Cert.from_file("wiktor.asc")))
```

### CertD integration

This library exposes [OpenPGP Certificate Directory][CERT-D]
integration, which allows storing and retrieving OpenPGP certificates
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
Cards (like YubiKey or Nitrokey).

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

signed = sign(signer, "data to be signed".encode("utf8"))
print(f"Signed data: {signed}")
```

As well as for decryption:

```python
decryptor = card.decryptor("123456")

sender = Cert.from_file("passwd.pgp")
receiver = Cert.from_file("no-passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.secrets().signer("hunter22"), recipients = [receiver], bytes = content.encode("utf8"))

print(f"Encrypted data: {encrypted}")

decrypted = decrypt(decryptor = decryptor, bytes = encrypted)

assert content == decrypted.bytes.decode("utf8");
```

Note that while this package allows using cards for signing and
decryption, the provisioning process is not supported.  [OpenPGP card
tools][] can be used to initialize the card.

[OpenPGP card tools]: https://crates.io/crates/openpgp-card-tools

## License

This project is licensed under [Apache License, Version 2.0][APL].

[APL]: https://www.apache.org/licenses/LICENSE-2.0.html

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the package by you shall be under the terms
and conditions of this license, without any additional terms or
conditions.

## Sponsors

My work is supported by these generous organizations (alphabetical
order):

  - [nlnet.nl](https://nlnet.nl/)
  - [pep.foundation](https://pep.foundation/)
  - [sovereigntechfund.de](https://sovereigntechfund.de/en.html)
