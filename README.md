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
[9580]: https://www.rfc-editor.org/rfc/rfc9580

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
gpg --batch --pinentry-mode loopback --passphrase hunter22 --quick-gen-key passwd@example.com rsa sign,encrypt
gpg --batch --pinentry-mode loopback --passphrase hunter22 --export-secret-key passwd@example.com > passwd.pgp

# generate a key without password
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key no-passwd@example.com rsa sign,encrypt
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
print(f"Signed data: {signed!r}")
assert "PGP MESSAGE" in str(signed)

detached = sign(
    s.secrets.signer(), "data to be signed".encode("utf8"), mode=SignatureMode.DETACHED
)
print(f"Detached signature: {detached!r}")
assert "PGP SIGNATURE" in str(detached)

clear = sign(
    s.secrets.signer(), "data to be signed".encode("utf8"), mode=SignatureMode.CLEAR
)
print(f"Clear signed: {clear!r}")
assert "PGP SIGNED MESSAGE" in str(clear)
```

### sign_file

Signs data from a file and writes the signed output to another file:

```python
from pysequoia import sign_file, SignatureMode
import tempfile, os

s = Cert.from_file("signing-key.asc")

# create a file with data to sign
with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
    inp.write("data to be signed".encode("utf8"))
    input_path = inp.name

with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
    output_path = out.name

sign_file(s.secrets.signer(), input_path, output_path)
signed = open(output_path, "rb").read()
assert b"PGP MESSAGE" in signed

# detached signature to file
with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as out:
    detached_path = out.name

sign_file(s.secrets.signer(), input_path, detached_path, mode=SignatureMode.DETACHED)
detached = open(detached_path, "rb").read()
assert b"PGP SIGNATURE" in detached

os.unlink(input_path)
os.unlink(output_path)
os.unlink(detached_path)
```

### verify

Verifies signed data and returns verified data:

```python
from pysequoia import verify

# sign some data
signing_key = Cert.from_file("signing-key.asc")
signed = sign(s.secrets.signer(), "data to be signed".encode("utf8"))


def get_certs_verify(key_ids):
    # key_ids is an array of required signing keys
    print(f"For verification, we need these keys: {key_ids}")
    return [signing_key]


# verify the data
result = verify(signed, get_certs_verify)
assert result.bytes.decode("utf8") == "data to be signed"

# let's check the valid signature's certificate and signing subkey fingerprints
assert result.valid_sigs[0].certificate == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
assert result.valid_sigs[0].signing_key == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
```

The function that returns certificates (here `get_certs_verify`) may return more certificates than necessary.

Detached signatures can be verified by passing additional parameter with the detached signature:

```python
data = "data to be signed".encode("utf8")
detached = sign(s.secrets.signer(), data, mode=SignatureMode.DETACHED)
signature = Sig.from_bytes(detached)

result = verify(bytes=data, store=get_certs_verify, signature=signature)

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
    signature = Sig.from_bytes(detached)

    tmp.write(data)
    tmp.close()

    # verify a detached signature against a file name
    result = verify(file=tmp.name, store=get_certs_verify, signature=signature)

    # let's check the valid signature's certificate and signing subkey fingerprints
    assert (
        result.valid_sigs[0].certificate == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
    )
    assert (
        result.valid_sigs[0].signing_key == "afcf5405e8f49dbcd5dc548a86375b854b86acf9"
    )
```

`verify` succeeds if *at least one* correct signature has been made by any of the certificates supplied. If you need more advanced policies they can be implemented by inspecting the `valid_sigs` property.

### encrypt

Signs and encrypts a string to one or more recipients:

```python
from pysequoia import encrypt

s = Cert.from_file("passwd.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())
content = "content to encrypt"
encrypted = encrypt(
    signer=s.secrets.signer("hunter22"), recipients=[r], bytes=content.encode("utf8")
)
print(f"Encrypted data: {encrypted.decode('utf8')}")
```

The `signer` argument is optional and when omitted the function will return an unsigned (but encrypted) message.

Encryption to symmetric keys is available via the `passwords` optional argument:

```python
from pysequoia import encrypt

content = "content to encrypt"
encrypted = encrypt(passwords=["sekrit"], bytes=content.encode("utf8"))
print(f"Encrypted data: {encrypted.decode('utf8')}")
```

### encrypt_file

Encrypts data from a file and writes the encrypted output to another file:

```python
from pysequoia import encrypt_file
import tempfile, os

s = Cert.from_file("passwd.pgp")
r = Cert.from_bytes(open("wiktor.asc", "rb").read())

# create a file with content to encrypt
with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
    inp.write("content to encrypt".encode("utf8"))
    input_path = inp.name

with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
    output_path = out.name

encrypt_file(
    signer=s.secrets.signer("hunter22"),
    recipients=[r],
    input=input_path,
    output=output_path,
)
assert b"PGP MESSAGE" in open(output_path, "rb").read()

os.unlink(input_path)
os.unlink(output_path)
```

### decrypt

Decrypts plain data:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))

decrypted = decrypt(decryptor=receiver.secrets.decryptor("hunter22"), bytes=encrypted)

assert content == decrypted.bytes.decode("utf8")
# this message did not contain any valid signatures
assert len(decrypted.valid_sigs) == 0
```

Decrypt can also verify signatures while decrypting:

```python
from pysequoia import decrypt

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(
    signer=sender.secrets.signer(), recipients=[receiver], bytes=content.encode("utf8")
)


def get_certs_decrypt(key_ids):
    print(f"For verification after decryption, we need these keys: {key_ids}")
    return [sender]


decrypted = decrypt(
    decryptor=receiver.secrets.decryptor("hunter22"),
    bytes=encrypted,
    store=get_certs_decrypt,
)

assert content == decrypted.bytes.decode("utf8")

# let's check the valid signature's certificate and signing subkey fingerprints
assert decrypted.valid_sigs[0].certificate == sender.fingerprint
assert decrypted.valid_sigs[0].signing_key == sender.fingerprint
```

Here, the same remarks as to [`verify`](#verify) also apply.

Decryption using symmetric keys is available via the `passwords` optional argument:

```python
from pysequoia import encrypt

content = "content to encrypt"
encrypted = encrypt(passwords=["sekrit"], bytes=content.encode("utf8"))
print(f"Encrypted data: {encrypted.decode('utf8')}")
decrypted = decrypt(passwords=["sekrit"], bytes=encrypted)
print(f"Decrypted bytes: {decrypted.bytes!r}")

assert content == decrypted.bytes.decode("utf8")
```

### decrypt_file

Decrypts data from a file and writes the decrypted output to another file:

```python
from pysequoia import decrypt_file
import tempfile, os

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))

# write encrypted data to a file
with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
    inp.write(encrypted)
    input_path = inp.name

with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
    output_path = out.name

decrypted = decrypt_file(
    decryptor=receiver.secrets.decryptor("hunter22"),
    input=input_path,
    output=output_path,
)

# content is written to the output file, not returned in memory
assert decrypted.bytes is None

# read decrypted content from the output file
assert open(output_path, "rb").read().decode("utf8") == content

# this message did not contain any valid signatures
assert len(decrypted.valid_sigs) == 0

os.unlink(input_path)
os.unlink(output_path)
```

Decrypt file can also verify signatures while decrypting:

```python
from pysequoia import decrypt_file
import tempfile, os

sender = Cert.from_file("no-passwd.pgp")
receiver = Cert.from_file("passwd.pgp")

content = "Red Green Blue"

encrypted = encrypt(
    signer=sender.secrets.signer(), recipients=[receiver], bytes=content.encode("utf8")
)

# write encrypted data to a file
with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
    inp.write(encrypted)
    input_path = inp.name

with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
    output_path = out.name


def get_certs_decrypt_file(key_ids):
    print(f"For verification after decryption, we need these keys: {key_ids}")
    return [sender]


decrypted = decrypt_file(
    decryptor=receiver.secrets.decryptor("hunter22"),
    input=input_path,
    output=output_path,
    store=get_certs_decrypt_file,
)

assert open(output_path, "rb").read().decode("utf8") == content

# let's check the valid signature's certificate and signing subkey fingerprints
assert decrypted.valid_sigs[0].certificate == sender.fingerprint
assert decrypted.valid_sigs[0].signing_key == sender.fingerprint

os.unlink(input_path)
os.unlink(output_path)
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
print(f"Bytes of the cert: {bytes(cert)!r}")
```

By default no secret parts are exported and they need to be manually accessed:

```python
if cert.secrets is not None:
    print(f"Armored TSK: {cert.secrets}")
    print(f"Bytes of the TSK: {bytes(cert.secrets)!r}")
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
cert = Cert.generate(user_ids=["First", "Second", "Third"])
assert len(cert.user_ids) == 3
```

Newly generated certificates are usable in both encryption and signing
contexts:

```python
alice = Cert.generate("Alice <alice@example.com>")
bob = Cert.generate("Bob <bob@example.com>")

content = "content to encrypt"

encrypted = encrypt(
    signer=alice.secrets.signer(), recipients=[bob], bytes=content.encode("utf8")
)
print(f"Encrypted data: {encrypted!r}")
```

The default is to generate keys according to [RFC4880][4880]. By
providing a `profile` parameter to the generate function, [modern PGP
keys][9580] can also be generated:

```python
from pysequoia import Profile

mary = Cert.generate("Modern Mary <mary@example.com", profile=Profile.RFC9580)
print(f"Generated cert with fingerprint {mary.fingerprint}:\n{mary}")
```

Note that legacy PGP implementations may not be able to consume these
certificates yet.

#### Expiration

The expiration is controlled via `validity_seconds` keyword argument:

```python
assert Cert.generate(user_id="test", validity_seconds=3600).expiration is not None
```

Using `None` generates a certificate with no expiration:

```python
assert Cert.generate(user_id="test", validity_seconds=None).expiration is None
```

By default certificates are generated *with* expiration time:

```python
assert Cert.generate("test").expiration is not None
```

> [!WARNING]
> If you rely on a particular value of expiration, set the argument explicitly.
> The current default (3 * 52 * 7 * 24 * 60 * 60) will change to `None`.

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
assert len(cert.user_ids) == 1
cert = cert.add_user_id(
    value="Alice <alice@company.invalid>", certifier=cert.secrets.certifier()
)

assert len(cert.user_ids) == 2
```

Revoking User IDs:

```python
cert = Cert.generate("Bob <bob@example.com>")

cert = cert.add_user_id(
    value="Bob <bob@company.invalid>", certifier=cert.secrets.certifier()
)
assert len(cert.user_ids) == 2

# create User ID revocation
revocation = cert.revoke_user_id(
    user_id=cert.user_ids[1], certifier=cert.secrets.certifier()
)

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

assert notation.key == "proof@metacode.biz"
assert notation.value == "dns:metacode.biz?type=TXT"
```

Notations can also be added:

```python
from pysequoia import Notation

cert = Cert.from_file("signing-key.asc")

# No notations initially
assert len(cert.user_ids[0].notations) == 0
cert = cert.set_notations(
    cert.secrets.certifier(), [Notation("proof@metacode.biz", "dns:metacode.biz")]
)

# Has one notation now
print(str(cert.user_ids[0].notations))
assert len(cert.user_ids[0].notations) == 1
# Check the notation data
notation = cert.user_ids[0].notations[0]

assert notation.key == "proof@metacode.biz"
assert notation.value == "dns:metacode.biz"
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
cert = cert.set_expiration(expiration=expiration, certifier=cert.secrets.certifier())
assert str(cert.expiration) == "2021-11-04 00:05:23+00:00"
```

### Key revocation

Certs can be revoked. While [expiration makes the key unusable
temporarily][EXP] to encourage the user to refresh a copy revocation is
irreversible.

[EXP]: https://blogs.gentoo.org/mgorny/2018/08/13/openpgp-key-expiration-is-not-a-security-measure/

```python
cert = Cert.generate("Test Revocation <revoke@example.com>")
revocation = cert.revoke(certifier=cert.secrets.certifier())

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

assert sig.issuer_fingerprint == "e8f23996f23218640cb44cbe75cf5ac418b8e74c"
assert sig.issuer_key_id == "75cf5ac418b8e74c"
assert sig.created == datetime.fromisoformat("2023-07-19T18:14:01+00:00")
assert sig.expiration == None
assert sig.signers_user_id == None
```

## Packet iteration

The `PacketPile` class provides low-level access to individual OpenPGP
packets in a key block, signed message, or other OpenPGP data. Each
packet exposes a `tag` property identifying the packet type, along with
type-specific accessors for extracting fields.

```python
from pysequoia.packet import PacketPile, Tag, SignatureType

cert = Cert.generate("Test <test@example.com>")
pile = PacketPile.from_bytes(bytes(cert))

for packet in pile:
    if packet.tag == Tag.PublicKey or packet.tag == Tag.PublicSubkey:
        print(
            f"Key: fpr={packet.fingerprint}, algo={packet.key_algorithm}, created={packet.key_created}"
        )

    elif packet.tag == Tag.UserID:
        print(
            f"User ID: {packet.user_id} (name={packet.user_id_name}, email={packet.user_id_email})"
        )

    elif packet.tag == Tag.Signature:
        print(
            f"Signature: type={packet.signature_type}, hash={packet.hash_algorithm}, created={packet.signature_created}"
        )
        if packet.issuer_fingerprint is not None:
            print(f"  issuer: {packet.issuer_fingerprint}")
        if packet.signature_validity_period is not None:
            print(f"  expires in: {packet.signature_validity_period}")
        if packet.signature_expiration_time is not None:
            print(f"  expiration time: {packet.signature_expiration_time}")
        if packet.key_flags is not None:
            print(f"  key flags: {packet.key_flags}")
        if (
            packet.signature_type == SignatureType.DirectKey
            and packet.key_validity_period is not None
        ):
            print(f"  key validity period: {packet.key_validity_period}")
```

Individual packets also carry their raw body bytes (without the tag and
length header), which can be useful for hashing or storing packet data:

```python
from pysequoia.packet import PacketPile, Tag

packet = list(PacketPile.from_bytes(bytes(cert)))[0]
assert packet.tag == Tag.PublicKey
assert len(packet.body) > 0
```

## ASCII armor

The `armor` function wraps raw binary data in ASCII armor, adding the
appropriate header, base64 encoding, and CRC24 checksum:

```python
from pysequoia import armor, ArmorKind

cert = Cert.generate("Test <test@example.com>")
armored = armor(bytes(cert), ArmorKind.PublicKey)  # same as: str(cert)
assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in armored
assert "-----END PGP PUBLIC KEY BLOCK-----" in armored
```

Other armor kinds are available for different data types:

```python
from pysequoia import armor, ArmorKind

armored_msg = armor(b"dummy data", ArmorKind.Message)
assert "BEGIN PGP MESSAGE" in armored_msg

armored_sig = armor(b"dummy data", ArmorKind.Signature)
assert "BEGIN PGP SIGNATURE" in armored_sig
```

Note that both `Cert` and `Sig` when converted to strings (`str(...)`)
will produce correct ASCII-armored representation.

## License

This project is licensed under [Apache License, Version 2.0][APL].

[APL]: https://www.apache.org/licenses/LICENSE-2.0.html

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the package by you shall be under the terms
and conditions of this license, without any additional terms or
conditions.
