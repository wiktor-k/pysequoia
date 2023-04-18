# STF

## Design and Implement a Python API for Sequoia

Python is a popular programming language. We have received many requests over
the past few years to add first-class for Python to Sequoia. For instance, SecureDrop
is implemented in Python, and uses OpenPGP. This project will implement Python
bindings for Sequoia's high-level functionality.

For this project, we will do the following:

### Design and implement a high-level Python API for standard OpenPGP operations

Survey existing Python projects to determine the commonly used
functionality.

Expose functionality related to the following areas:

  - [Signatures](https://wiktor.codeberg.page/pysequoia/#sign),
  - [Encryption](https://wiktor.codeberg.page/pysequoia/#encrypt) and [decryption](https://wiktor.codeberg.page/pysequoia/#decrypt),
  - Certificate manipulation ([setting expiration](https://wiktor.codeberg.page/pysequoia/#key-expiration), [adding User IDs](https://wiktor.codeberg.page/pysequoia/#user-ids), etc.)

(50% - 80 days)

Milestone status: ✅ 100% complete.

Future work:

  - [Add `verify` function](https://codeberg.org/wiktor/pysequoia/issues/54),
  - [Add support for encrypting/decrypting/signing files](https://codeberg.org/wiktor/pysequoia/issues/65),
  - [Add certificate inspection](https://codeberg.org/wiktor/pysequoia/issues/56),
  - [Check key validity function](https://codeberg.org/wiktor/pysequoia/issues/52).

### Design and implement a Python API for accessing a cert-d certificate store

See https://sequoia-pgp.gitlab.io/pgp-cert-d/.

Implemented using [`Store` class](https://wiktor.codeberg.page/pysequoia/#certd-integration).

(25% - 40 days)

Milestone status: ✅ 100% complete.

Future work:

  - [Consider using sequoia-cert-store](https://codeberg.org/wiktor/pysequoia/issues/15).

### Design and implement a Python API for retrieval and publication of certificates

This will focus on [HKPS](https://wiktor.codeberg.page/pysequoia/#key-server), [WKD](https://wiktor.codeberg.page/pysequoia/#wkd) and [VKS](https://wiktor.codeberg.page/pysequoia/#vks).

(25% - 40 days)

Milestone status: ✅ 100% complete.

Future work:

  - [Add Keyserver.search for returning multiple certificates](https://codeberg.org/wiktor/pysequoia/issues/58),
  - [WKD.search should return an array](https://codeberg.org/wiktor/pysequoia/issues/57).

Total cost: 160 days
