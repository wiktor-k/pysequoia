# STF

The following describes goals set in the initial document as well as links to actual code changes that implement these goals.

1. Design and Implement a Python API for Sequoia

For this project, we will do the following:

- Design and implement a high-level Python API for standard OpenPGP operations
  Comment: A vast array of OpenPGP operations is available through our Python package. The API description is available at https://pypi.org/project/pysequoia/

- Survey existing Python projects to determine the commonly used functionality.
  Comment: We selected keyringctl and gpg-lacre as two high-profile projects using OpenPGP and struggling with either GnuPG or low-level command line invocations

- Expose functionality related to the following areas:

  - Signatures.
    Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#sign
  - Encryption.
    Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#encrypt
  - Decryption.
    Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#decrypt
  - Certificate manipulation:
      - setting expiration.
        Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#key-expiration
      - adding User IDs.
        Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#user-ids

Additional work done:

  - certificate generation: https://codeberg.org/wiktor/pysequoia#generate
  - certificate merging: https://codeberg.org/wiktor/pysequoia#merge
  - revoking User IDs: https://codeberg.org/wiktor/pysequoia#user-ids
  - notations manipulation: https://codeberg.org/wiktor/pysequoia#notations
  - support for OpenPGP Cards: https://codeberg.org/wiktor/pysequoia#openpgp-cards
  - comprehensive test suite: https://codeberg.org/wiktor/pysequoia#testing covering smartcards as well as documentation

2. Design and implement a Python API for accessing a cert-d certificate store

Comment: Feature implemented using `Store` class. Documentation available at: https://wiktor.codeberg.page/pysequoia/#certd-integration

3. Design and implement a Python API for retrieval and publication of certificates

- HKPS.
   Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#key-server
- WKD.
   Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#wkd
- VKS.
   Comment: Feature implemented. Documentation available at: https://wiktor.codeberg.page/pysequoia/#vks

Additional work done:

  - Add Keyserver.search for returning multiple certificates: https://codeberg.org/wiktor/pysequoia/issues/58

4. Integrations for other projects (in progress):
    - keyringctl: https://gitlab.archlinux.org/archlinux/archlinux-keyring/-/merge_requests/225
    - gpg-lacre: https://git.disroot.org/Disroot/gpg-lacre/pulls/127

