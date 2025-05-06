<img src="https://github.com/wiktor-k/pysequoia/raw/main/doc/logo.png" align="right" width="150" height="150" />

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

PyPI version of PySequoia includes native wheels for a variety of architectures and OS combinations.
If you are using a combination that is not yet provided a [Rust toolchain][RUSTUP] will be necessary for the installation to succeed.

[RUSTUP]: https://rustup.rs/

## Testing

This entire document is used for end-to-end integration tests that
exercise the package's API surface.

The tests assume that these keys exist:

```bash
# generate a key with password
gpg --batch --pinentry-mode loopback --passphrase hunter22 --quick-gen-key passwd@example.com
gpg --batch --pinentry-mode loopback --passphrase hunter22 --export-secret-key passwd@example.com > passwd.pgp

# generate a key without password
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key no-passwd@example.com future-default
gpg --batch --pinentry-mode loopback --passphrase '' --export-secret-key no-passwd@example.com > no-passwd.pgp
```

## Functions

All examples assume that these basic classes have been imported:

```python
from pysequoia import Cert, Sig
```

### sign

Signs data and returns armored output:

```python
from pysequoia import sign, SignatureMode

s = Cert.from_file("signing-key.asc")
signed = sign(s.secrets.signer(), "data to be signed".encode("utf8"))
print(f"Signed data: {signed}")
assert "PGP MESSAGE" in str(signed)

detached = sign(s.secrets.signer(), "data to be signed".encode("utf8"), mode=SignatureMode.DETACHED)
print(f"Detached signature: {detached}")
assert "PGP SIGNATURE" in str(detached)

clear = sign(s.secrets.signer(), "data to be signed".encode("utf8"), mode=SignatureMode.CLEAR)
print(f"Clear signed: {clear}")
assert "PGP SIGNED MESSAGE" in str(clear)
```

### verify

Verifies signed data and returns verified data:

```python
from pysequoia import verify

# sign some data
signing_key = Cert.from_file("signing-key.asc")
signed = sign(s.secrets.signer(), "data to be signed".encode("utf8"))

def get_certs(key_ids):
  # key_ids is an array of required signing keys
  print(f"For verification, we need these keys: {key_ids}")
  return [signing_key]

# verify the data
result = verify(signed, get_certs)
assert result.bytes.decode("utf8") == "data to be signed"

# let's check the valid signature's certificate and signing subkey fingerprints
assert result.valid_sigs[0].certificate == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
assert result.valid_sigs[0].signing_key == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
```

The function that returns certificates (here `get_certs`) may return more certificates than necessary.

Detached signatures can be verified by passing additional parameter with the detached signature:

```python
data = "data to be signed".encode("utf8")
detached = sign(s.secrets.signer(), data, mode=SignatureMode.DETACHED)
detached = Sig.from_bytes(detached)

result = verify(bytes=data, store=get_certs, signature=detached)

# let's check the valid signature's certificate and signing subkey fingerprints
assert result.valid_sigs[0].certificate == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
assert result.valid_sigs[0].signing_key == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
```

This function can also work with files directly, which is beneficial if the file to be verified is large:

```python
import tempfile
with tempfile.NamedTemporaryFile(delete=False) as tmp:
  data = "data to be signed".encode("utf8")
  detached = sign(s.secrets.signer(), data, mode=SignatureMode.DETACHED)
  detached = Sig.from_bytes(detached)

  tmp.write(data)
  tmp.close()

  # verify a detached signature against a file name
  result = verify(file=tmp.name, store=get_certs, signature=detached)

  # let's check the valid signature's certificate and signing subkey fingerprints
  assert result.valid_sigs[0].certificate == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
  assert result.valid_sigs[0].signing_key == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
```

`verify` succeeds if *at least one* correct signature has been made by any of the certificates supplied. If you need more advanced policies they can be implemented by inspecting the `valid_sigs` property.

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("passwd.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
content = "content to encrypt".encode("utf8")
encrypted = encrypt(signer = s.secrets.signer("hunter22"), recipients = [r], bytes = content).decode("utf8")
print(f"Encrypted data: {encrypted}")
```

The `signer` argument is optional and when omitted the function will return an unsigned (but encrypted) message.

### decrypt

Decrypts plain data:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(recipients = [receiver], bytes = content.encode("utf8"))

decrypted = decrypt(decryptor = receiver.secrets.decryptor("hunter22"), bytes = encrypted)

assert content == decrypted.bytes.decode("utf8");

# this message did not contain any valid signatures
assert len(decrypted.valid_sigs) == 0
```

Decrypt can also verify signatures while decrypting:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(signer = sender.secrets.signer(), recipients = [receiver], bytes = content.encode("utf8"))

def get_certs(key_ids):
  print(f"For verification after decryption, we need these keys: {key_ids}")
  return [sender]

decrypted = decrypt(decryptor = receiver.secrets.decryptor("hunter22"), bytes = encrypted, store = get_certs)

assert content == decrypted.bytes.decode("utf8");

# let's check the valid signature's certificate and signing subkey fingerprints
assert decrypted.valid_sigs[0].certificate == sender.fingerprint
assert decrypted.valid_sigs[0].signing_key == sender.fingerprint
```

Here, the same remarks as to [`verify`](#verify) also apply.

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
print(f"Bytes of the cert: {bytes(cert)}")
```

### Parsing

Certificates can be parsed from files (`Cert.from_file`) or bytes in
memory (`Cert.from_bytes`).

```python
cert1 = Cert.generate("Test <test@example.com>")
buffer = bytes(cert1)

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

buffer = bytes(cert1) + bytes(cert2) + bytes(cert3)
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

content = "content to encrypt".encode("utf8")

encrypted = encrypt(signer = alice.secrets.signer(), recipients = [bob], bytes = content)
print(f"Encrypted data: {encrypted}")
```

### merge

Merges packets from a new version into an old version of a certificate:

```python
old = Cert.from_file("wiktor.asc")
new = Cert.from_file("wiktor-fresh.asc")
merged = old.merge(new)
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
cert = Cert.from_bytes(bytes(cert) + bytes(revocation))
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
revoked_cert = Cert.from_bytes(bytes(cert) + bytes(revocation))
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

## Signatures

Detached signatures can be read directly from files (`Sig.from_file`) or bytes in memory (`Sig.from_bytes`):

```python
from pysequoia import Sig

sig = Sig.from_file("sig.pgp")

print(f"Parsed signature: {repr(sig)}")

assert sig.issuer_fpr == "e8f23996f23218640cb44cbe75cf5ac418b8e74c"
assert sig.created == datetime.fromisoformat("2023-07-19T18:14:01+00:00")
```

## License

This project is licensed under [Apache License, Version 2.0][APL].

[APL]: https://www.apache.org/licenses/LICENSE-2.0.html

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the package by you shall be under the terms
and conditions of this license, without any additional terms or
conditions.
