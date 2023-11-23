<img src="https://camo.githubusercontent.com/2405a5e252c89f97bb4ec3542e1c56c0571551cf52615dbcf728d38c5279bfc0/68747470733a2f2f636f6465626572672e6f72672f77696b746f722f7079736571756f69612f7261772f6272616e63682f6d61696e2f646f632f6c6f676f2e706e67" align="right" width="150" height="150" />

# PySequoia

[![PyPI version](https://badge.fury.io/py/pysequoia.svg)](https://pypi.org/project/pysequoia/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/pysequoia.svg?label=PyPI%20downloads)](
https://pypi.org/project/pysequoia/)
[![CI](https://github.com/wiktor-k/pysequoia/actions/workflows/ci.yml/badge.svg)](https://github.com/wiktor-k/pysequoia/actions/workflows/ci.yml)

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
CARD_ADMIN="opgpcard admin --card 0000:00000000 --admin-pin pin"
$CARD_ADMIN import full-key.asc
$CARD_ADMIN name "John Doe"
$CARD_ADMIN url "https://example.com/key.pgp"
$CARD_ADMIN touch --key SIG --policy Fixed
$CARD_ADMIN touch --key DEC --policy Off
$CARD_ADMIN touch --key AUT --policy Fixed
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
encrypted = encrypt(signer = s.secrets.signer("hunter22"), recipients = [r], bytes = bytes).decode("utf8")
print(f"Encrypted data: {encrypted}")
```

### decrypt

Decrypts data:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.secrets.signer(), recipients = [receiver], bytes = content.encode("utf8"))

decrypted = decrypt(decryptor = receiver.secrets.decryptor("hunter22"), bytes = encrypted)

assert content == decrypted.bytes.decode("utf8");
```

### sign

Signs data and returns armored output:

```python
from pysequoia import sign

s = Cert.from_file("signing-key.asc")
signed = sign(s.secrets.signer(), "data to be signed".encode("utf8"))
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

[SP]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/policy/struct.StandardPolicy.html

Certificates have two forms, one is ASCII armored and one is raw bytes:

```python
cert = Cert.generate("Test <test@example.com>")

print(f"Armored cert: {cert}")
print(f"Bytes of the cert: {cert.bytes()}")
```

### Parsing

Certificates can be parsed from files (`Cert.from_file`) or bytes in
memory (`Cert.from_bytes`).

```python
cert1 = Cert.generate("Test <test@example.com>")
buffer = cert1.bytes()

parsed_cert = Cert.from_bytes(buffer)
assert str(parsed_cert.user_ids[0]) == "Test <test@example.com>"
```

They can also be picked from "keyring" files (`Cert.split_file`) or
bytes in memory (`Cert.split_bytes`) which are collections of binary
certificates.

```python
cert1 = Cert.generate("Test 1 <test-1@example.com>")
cert2 = Cert.generate("Test 2 <test-2@example.com>")
cert3 = Cert.generate("Test 3 <test-3@example.com>")

buffer = cert1.bytes() + cert2.bytes() + cert3.bytes()
certs = Cert.split_bytes(buffer)
assert len(certs) == 3
```

### generate

Creates a new general purpose key with a given User ID:

```python
alice = Cert.generate("Alice <alice@example.com>")
fpr = alice.fingerprint
print(f"Generated cert with fingerprint {fpr}:\n{alice}")
```

Multiple User IDs can be passed as a list to the `generate` function:

```python
cert = Cert.generate(user_ids = ["First", "Second", "Third"])
assert len(cert.user_ids) == 3
```

Newly generated certificates are usable in both encryption and signing
contexts:

```python
alice = Cert.generate("Alice <alice@example.com>")
bob = Cert.generate("Bob <bob@example.com>")

bytes = "content to encrypt".encode("utf8")

encrypted = encrypt(signer = alice.secrets.signer(), recipients = [bob], bytes = bytes)
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

cert = cert.add_user_id(value = "Alice <alice@company.invalid>", certifier = cert.secrets.certifier())

assert len(cert.user_ids) == 2;
```

Revoking User IDs:

```python
cert = Cert.generate("Bob <bob@example.com>")

cert = cert.add_user_id(value = "Bob <bob@company.invalid>", certifier = cert.secrets.certifier())
assert len(cert.user_ids) == 2

# create User ID revocation
revocation = cert.revoke_user_id(user_id = cert.user_ids[1], certifier = cert.secrets.certifier())

# merge the revocation with the cert
cert = Cert.from_bytes(cert.bytes() + revocation.bytes())
assert len(cert.user_ids) == 1
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

cert = cert.set_notations(cert.secrets.certifier(), [Notation("proof@metacode.biz", "dns:metacode.biz")])

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
cert = cert.set_expiration(expiration = expiration, certifier = cert.secrets.certifier())
assert str(cert.expiration) == "2021-11-04 00:05:23+00:00"
```

### Key revocation

Certs can be revoked. While [expiration makes the key unusable
temporarily][EXP] to encourage the user to refresh a copy revocation is
irreversible.

[EXP]: https://blogs.gentoo.org/mgorny/2018/08/13/openpgp-key-expiration-is-not-a-security-measure/

```python
cert = Cert.generate("Test Revocation <revoke@example.com>")
revocation = cert.revoke(certifier = cert.secrets.certifier())

# creating revocation signature does not revoke the key
assert not cert.is_revoked

# importing revocation signature marks the key as revoked
revoked_cert = Cert.from_bytes(cert.bytes() + revocation.bytes())
assert revoked_cert.is_revoked
```

## Secret keys

Certificates generated through `Cert.generate()` contain secret keys
and can be used for signing and decryption.

To avoid accidental leakage secret keys are never directly printed
when the Cert is written to a string. To enable this behavior use
`Cert.secrets`. `secrets` returns `None` on certificates which do
not contain any secret key material ("public keys").

```python
c = Cert.generate("Testing key <test@example.com>")
assert c.has_secret_keys

# by default only public parts are exported
public_parts = Cert.from_bytes(f"{c}".encode("utf8"))
assert not public_parts.has_secret_keys
assert public_parts.secrets is None

# to export secret parts use the following:
private_parts = Cert.from_bytes(f"{c.secrets}".encode("utf8"))
assert private_parts.has_secret_keys
```

## Certificate management

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
assert card.cardholder == "John Doe"
assert card.cert_url == "https://example.com/key.pgp"
```

Cards provide `keys` property that can be used to see which keys are imported
on the card:

```python
keys = card.keys
print(f"Keys: {keys}")
assert len(keys) == 3

assert keys[0].fingerprint == "ddc3e03c91fb52ca2d95c2444566f2743ed5f382"
assert "sign" in keys[0].usage
assert keys[0].touch_required

assert keys[1].fingerprint == "689e152a7420be13dcaf2c142ac27adc1db9395e"
assert "decrypt" in keys[1].usage
assert not keys[1].touch_required

assert keys[2].fingerprint == "731fbca93ce9821347bf8e696444723371d3c650"
assert "authenticate" in keys[2].usage
assert keys[2].touch_required
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
receiver = Cert.from_file("full-key.asc")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.secrets.signer("hunter22"), recipients = [receiver], bytes = content.encode("utf8"))

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

My work was supported by these generous organizations (alphabetical
order):

  - [nlnet.nl](https://nlnet.nl/)
  - [pep.foundation](https://pep.foundation/)
  - [sovereigntechfund.de](https://sovereigntechfund.de/en.html)
