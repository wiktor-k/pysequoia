from .packet import HashAlgorithm, Packet, PublicKeyAlgorithm, SignatureType
from collections.abc import Sequence
from datetime import datetime, timedelta
from os import PathLike
from typing import Any, Final, final

@final
class ArmorKind:
    """
    The type of ASCII armor to use when wrapping OpenPGP data.
    """
    Message: Final[ArmorKind]
    """
    `PGP MESSAGE`
    """
    PublicKey: Final[ArmorKind]
    """
    `PGP PUBLIC KEY BLOCK`
    """
    SecretKey: Final[ArmorKind]
    """
    `PGP PRIVATE KEY BLOCK`
    """
    Signature: Final[ArmorKind]
    """
    `PGP SIGNATURE`
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class Cert:
    """
    An OpenPGP certificate (public key with associated user IDs, subkeys, and signatures).
    """
    def __bytes__(self, /) -> bytes:
        """
        Return the raw binary encoding of this certificate.
        """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str:
        """
        Return the ASCII-armored public key representation of this certificate.
        """
    def add_user_id(self, /, value: str, certifier: PySigner) -> Cert:
        """
        Add a User ID to this certificate, certified by the given signer.
        """
    @property
    def expiration(self, /) -> datetime |None:
        """
        The expiration time of this certificate, or `None` if it does not expire.
        """
    @property
    def fingerprint(self, /) -> str:
        """
        The fingerprint of this certificate's primary key, as a lowercase hex string.
        """
    @staticmethod
    def from_bytes(bytes: bytes) -> Cert:
        """
        Parse a certificate from a byte string.

        The bytes may be binary or ASCII-armored.
        """
    @staticmethod
    def from_file(path: str) -> Cert:
        """
        Parse a certificate from a file on disk.

        The file may be binary or ASCII-armored.
        """
    @staticmethod
    def from_packets(packets: Sequence[Packet]) -> Cert:
        """
        Build a certificate from a sequence of OpenPGP packets.

        The packets must form a valid certificate (a primary key followed by
        its associated user IDs, user attributes, subkeys, and signatures).
        """
    @staticmethod
    def generate(user_id: str |None = None, user_ids: Sequence[str] |None = None, profile: Profile |None = None, validity_seconds: int |None = ...) -> Cert:
        """
        Generate a new certificate with a certification-capable primary key,
        a signing subkey, and an encryption subkey.

        The generated certificate has a validity period of 3 years.
        """
    @property
    def has_secret_keys(self, /) -> bool:
        """
        Whether this certificate contains secret key material.
        """
    @property
    def is_revoked(self, /) -> bool:
        """
        Whether this certificate has been revoked.
        """
    def merge(self, /, new_cert: Cert) -> Cert:
        """
        Merge another certificate into this one, combining their packets.

        Both certificates must have the same primary key fingerprint.
        """
    def revoke(self, /, certifier: PySigner) -> Sig:
        """
        Create a revocation signature for this certificate.
        """
    def revoke_user_id(self, /, user_id: UserId, certifier: PySigner) -> Sig:
        """
        Create a revocation signature for the given User ID.
        """
    @property
    def secrets(self, /) -> Tsk |None:
        """
        Access the secret key material, if present.

        Returns `None` if the certificate does not contain secret keys.
        """
    def set_expiration(self, /, expiration: datetime, certifier: PySigner) -> Cert:
        """
        Set the expiration time of this certificate.
        """
    def set_notations(self, /, certifier: PySigner, notations: Sequence[Notation]) -> Cert:
        """
        Set notation data on the first User ID's binding signature.
        """
    @staticmethod
    def split_bytes(bytes: bytes) -> list[Cert]:
        """
        Parse multiple certificates from a byte string.

        Returns a list of all certificates found in the data.
        The bytes may be binary or ASCII-armored.
        """
    @staticmethod
    def split_file(path: str) -> list[Cert]:
        """
        Parse multiple certificates from a file on disk.

        Returns a list of all certificates found in the file.
        The file may be binary or ASCII-armored.
        """
    @property
    def user_ids(self, /) -> list[UserId]:
        """
        The non-revoked User IDs on this certificate.
        """

@final
class CipherSuite:
    """
    The cipher suite to use when generating keys.

    Controls which cryptographic algorithms are used for the primary key and subkeys.
    The PQC (post-quantum cryptography) suites require `Profile.RFC9580`.
    """
    Cv25519: Final[CipherSuite]
    """
    EdDSA and ECDH over Curve25519 (default)
    """
    Cv448: Final[CipherSuite]
    """
    EdDSA and ECDH over Curve448
    """
    MLDSA65_Ed25519: Final[CipherSuite]
    """
    Post-quantum: ML-DSA-65 + Ed25519 signing, ML-KEM-768 + X25519 encryption (v6 only)
    """
    MLDSA87_Ed448: Final[CipherSuite]
    """
    Post-quantum: ML-DSA-87 + Ed448 signing, ML-KEM-1024 + X448 encryption (v6 only)
    """
    P256: Final[CipherSuite]
    """
    ECDSA and ECDH over NIST P-256
    """
    P384: Final[CipherSuite]
    """
    ECDSA and ECDH over NIST P-384
    """
    P521: Final[CipherSuite]
    """
    ECDSA and ECDH over NIST P-521
    """
    RSA2k: Final[CipherSuite]
    """
    2048-bit RSA
    """
    RSA3k: Final[CipherSuite]
    """
    3072-bit RSA
    """
    RSA4k: Final[CipherSuite]
    """
    4096-bit RSA
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class Decrypted:
    """
    The result of a decryption or verification operation.

    Contains the decrypted/verified content (if available) and any valid signatures found.
    """
    @property
    def bytes(self, /) -> bytes |None:
        """
        The decrypted or verified content bytes, or `None` for file-based operations.
        """
    @property
    def valid_sigs(self, /) -> list[Any]:
        """
        The list of valid signatures found during verification.
        """

@final
class EncryptionAlgorithm:
    """
    The encryption algorithm to use when generating keys.

    Used with `Tsk.generate(encryption_algorithm=...)` to override the
    encryption algorithm independently of the cipher suite. Requires
    `Profile.RFC9580` for PQC algorithms (except `MLKEM768_X25519`).
    """
    MLKEM1024_X448: Final[EncryptionAlgorithm]
    """
    Composite ML-KEM-1024 + X448 (post-quantum)
    """
    MLKEM768_X25519: Final[EncryptionAlgorithm]
    """
    Composite ML-KEM-768 + X25519 (post-quantum)
    """
    X25519: Final[EncryptionAlgorithm]
    """
    X25519
    """
    X448: Final[EncryptionAlgorithm]
    """
    X448
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class Notation:
    """
    A key-value notation attached to an OpenPGP signature.
    """
    def __new__(cls, /, key: str, value: str) -> Notation:
        """
        Create a new notation with the given key and value.
        """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str: ...
    @property
    def key(self, /) -> str:
        """
        The notation key (name).
        """
    @property
    def value(self, /) -> str:
        """
        The notation value.
        """

@final
class Profile:
    """
    The OpenPGP profile to use when generating certificates.

    Controls which packet format and algorithms are used.
    """
    RFC4880: Final[Profile]
    RFC9580: Final[Profile]
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class PyDecryptor:
    """
    A decryption helper that holds the key material needed to decrypt messages.

    Obtain a `PyDecryptor` via `Tsk.decryptor()`.
    """

@final
class PySigner:
    """
    A handle to a signing key, used for creating signatures, certifications, and revocations.

    Obtain a `PySigner` via `Tsk.signer()` or `Tsk.certifier()`.
    """

@final
class Sig:
    """
    A detached OpenPGP signature.
    """
    def __bytes__(self, /) -> bytes:
        """
        Returns the raw binary encoding of the signature packet.
        """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str:
        """
        Return the ASCII-armored representation of the signature.
        """
    @property
    def created(self, /) -> datetime |None:
        """
        The time at which this signature was created.

        Returns `None` if the signature does not carry a creation time subpacket.
        """
    @property
    def expiration(self, /) -> datetime |None:
        """
        The time at which this signature expires, or `None` if it does not expire.

        Returns `None` if either subpacket is absent.
        """
    @staticmethod
    def from_bytes(bytes: bytes) -> Sig:
        """
        Loads a signature from a byte string.

        The bytes may be binary or ASCII-armored.
        """
    @staticmethod
    def from_file(path: str) -> Sig:
        """
        Loads a signature from a file on disk.

        The file may be binary or ASCII-armored.
        """
    @property
    def hash_algorithm(self, /) -> HashAlgorithm:
        """
        The hash algorithm used by this signature.
        """
    @property
    def issuer_fingerprint(self, /) -> str |None:
        """
        The fingerprint of the key that made this signature, as a lowercase hex string.

        Returns `None` if the signature does not carry an issuer fingerprint subpacket.
        """
    @property
    def issuer_fpr(self, /) -> str |None:
        """
        DEPRECATED: The fingerprint of the key that made this signature, as a lowercase hex string.

        Alias for `issuer_fingerprint`. Prefer `issuer_fingerprint` going forwards.

        Returns `None` if the signature does not carry an issuer fingerprint subpacket.
        Prefer this over `issuer_key_id` when available, as fingerprints are collision-resistant.
        """
    @property
    def issuer_key_id(self, /) -> str |None:
        """
        The short key ID of the key that made this signature, as a lowercase hex string.

        Returns `None` if the signature does not carry an issuer key ID subpacket.
        Prefer `issuer_fingerprint` over this where possible, as key IDs are not collision-resistant.
        """
    @property
    def key_algorithm(self, /) -> PublicKeyAlgorithm:
        """
        The public key algorithm used by this signature.
        """
    @property
    def key_validity_period(self, /) -> timedelta |None:
        """
        The key validity period as a timedelta from key creation.

        This is the duration after the key's creation time at which the key expires.
        Found in Subkey Binding and Direct Key signatures.
        Returns `None` if the subpacket is not present.
        """
    @property
    def signature_type(self, /) -> SignatureType:
        """
        The signature type (e.g. `SignatureType.SubkeyBinding`).
        """
    @property
    def signers_user_id(self, /) -> str |None:
        """
        The User ID of the signer, as declared in the signature's Signer's User ID subpacket.

        Returns `None` if the signature does not carry a Signer's User ID subpacket.
        Note that this value is self-reported by the signer and is not verified against any cert.
        """
    @property
    def version(self, /) -> int:
        """
        The version of this signature packet (e.g. 4 or 6).
        """

@final
class SignatureMode:
    """
    The mode of signature to produce.
    """
    CLEAR: Final[SignatureMode]
    DETACHED: Final[SignatureMode]
    INLINE: Final[SignatureMode]
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class SigningAlgorithm:
    """
    The signing algorithm to use when generating keys.

    Used with `Cert.generate(signing_algorithm=...)` to override the signing
    algorithm independently of the cipher suite. Requires `Profile.RFC9580`
    for PQC algorithms.
    """
    Ed25519: Final[SigningAlgorithm]
    """
    Ed25519
    """
    Ed448: Final[SigningAlgorithm]
    """
    Ed448
    """
    MLDSA65_Ed25519: Final[SigningAlgorithm]
    """
    Composite ML-DSA-65 + Ed25519 (post-quantum)
    """
    MLDSA87_Ed448: Final[SigningAlgorithm]
    """
    Composite ML-DSA-87 + Ed448 (post-quantum)
    """
    SLHDSA128f: Final[SigningAlgorithm]
    """
    SLH-DSA 128-bit fast signatures (post-quantum, stateless)
    """
    SLHDSA128s: Final[SigningAlgorithm]
    """
    SLH-DSA 128-bit small signatures (post-quantum, stateless)
    """
    SLHDSA256s: Final[SigningAlgorithm]
    """
    SLH-DSA 256-bit small signatures (post-quantum, stateless)
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class Tsk:
    """
    A certificate that contains secret key material.

    Provides access to signing, certification, and decryption operations
    that require private keys.
    """
    def __bytes__(self, /) -> bytes:
        """
        Return the raw binary encoding of this certificate.
        """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str:
        """
        Return the ASCII-armored secret key representation (Transferable Secret Key).
        """
    def certifier(self, /, password: str |None = None) -> PySigner:
        """
        Get a certifier using this certificate's certification-capable primary key.

        If the secret key is password-protected, provide the password to decrypt it.
        """
    def decryptor(self, /, password: str |None = None) -> PyDecryptor:
        """
        Get a decryptor using this certificate's encryption component key.

        If the secret key is password-protected, provide the password to decrypt it.
        """
    def extract_certificate(self, /) -> Cert:
        """
        Extracts public parts of this TSK.
        """
    @staticmethod
    def from_bytes(bytes: bytes) -> Tsk:
        """
        Parse a certificate from a byte string.

        The bytes may be binary or ASCII-armored.
        """
    @staticmethod
    def from_file(path: str) -> Tsk:
        """
        Parse a certificate from a file on disk.

        The file may be binary or ASCII-armored.
        """
    @staticmethod
    def from_packets(packets: Sequence[Packet]) -> Tsk:
        """
        Build a certificate from a sequence of OpenPGP packets.

        The packets must form a valid certificate (a primary key followed by
        its associated user IDs, user attributes, subkeys, and signatures).
        """
    @staticmethod
    def generate(user_id: str |None = None, user_ids: Sequence[str] |None = None, profile: Profile |None = None, cipher_suite: CipherSuite |None = None, validity_seconds: int |None = None, *, signing_algorithm: SigningAlgorithm |None = None, encryption_algorithm: EncryptionAlgorithm |None = None) -> Tsk:
        """
        Generate a new TSK with a certification-capable primary key,
        a signing subkey, and an encryption subkey.

        The generated certificate does not expire unless explicitly instructed.
        """
    def signer(self, /, password: str |None = None) -> PySigner:
        """
        Get a signer using this certificate's signing component key.

        If the secret key is password-protected, provide the password to decrypt it.
        """

@final
class UserId:
    """
    A User ID component of an OpenPGP certificate (e.g. `"Alice <alice@example.com>"`).
    """
    def __repr__(self, /) -> str: ...
    def __str__(self, /) -> str:
        """
        Return the User ID string value.
        """
    @property
    def notations(self, /) -> list[Notation]:
        """
        The human-readable notations from this User ID's binding signature.
        """

def armor(data: bytes, kind: ArmorKind) -> str:
    """
    Wrap raw OpenPGP data in ASCII armor.

    Takes raw binary OpenPGP data and an `ArmorKind` specifying the armor
    header type, and returns the ASCII-armored string.
    """

def decrypt(bytes: bytes, decryptor: PyDecryptor |None = None, store: Any |None = None, passwords: Sequence[str] = ...) -> Decrypted:
    """
    Decrypt an OpenPGP message from bytes.

    Provide either a `decryptor` (from a secret key) or `passwords` for password-based decryption.
    Optionally provide a `store` callback for signature verification during decryption.
    """

def decrypt_file(input: str |PathLike[str], output: str |PathLike[str], decryptor: PyDecryptor |None = None, store: Any |None = None, passwords: Sequence[str] = ...) -> Decrypted:
    """
    Decrypt an OpenPGP message from a file, writing the plaintext to another file.

    Provide either a `decryptor` (from a secret key) or `passwords` for password-based decryption.
    Optionally provide a `store` callback for signature verification during decryption.
    """

def encrypt(bytes: bytes, recipients: Sequence[Cert] = ..., signer: PySigner |None = None, passwords: Sequence[str] = ..., *, armor: bool = True) -> bytes:
    """
    Encrypt data for the given recipients and/or passwords.

    Optionally sign the message with the given `signer`.
    Set `armor=False` to produce binary output instead of ASCII-armored.
    """

def encrypt_file(input: str |PathLike[str], output: str |PathLike[str], recipients: Sequence[Cert] = ..., signer: PySigner |None = None, passwords: Sequence[str] = ..., *, armor: bool = True) -> None:
    """
    Encrypt a file for the given recipients and/or passwords, writing to an output file.

    Optionally sign the message with the given `signer`.
    Set `armor=False` to produce binary output instead of ASCII-armored.
    """

def sign(signer: PySigner, bytes: bytes, *, mode: SignatureMode = ..., armor: bool = True) -> bytes:
    """
    Sign data with the given signer.

    The `mode` controls whether the signature is inline (the default), detached, or cleartext.
    Set `armor=False` to produce binary output instead of ASCII-armored.
    """

def sign_file(signer: PySigner, input: str |PathLike[str], output: str |PathLike[str], *, mode: SignatureMode = ..., armor: bool = True) -> None:
    """
    Sign a file with the given signer, writing the result to an output file.

    The `mode` controls whether the signature is inline (the default), detached, or cleartext.
    Set `armor=False` to produce binary output instead of ASCII-armored.
    """

def verify(bytes: bytes |None = None, store: Any |None = None, file: str |PathLike[str] |None = None, signature: Sig |None = None) -> Decrypted:
    """
    Verify an OpenPGP signature.

    Provide either `bytes` or `file` as the signed data source. The `store` callback
    is called with a list of key ID strings and must return a list of `Cert` objects.
    For detached signature verification, pass a `Sig` object as `signature`.
    """
