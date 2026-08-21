from . import Notation
from datetime import datetime, timedelta
from typing import Any, Final, final

@final
class DataFormat:
    """
    The data format of a Literal Data packet.
    """
    Binary: Final[DataFormat]
    """
    Binary data
    """
    Text: Final[DataFormat]
    """
    Text data, encoding unspecified. Deprecated.
    """
    Unicode: Final[DataFormat]
    """
    UTF-8 text data
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class HashAlgorithm:
    """
    The hash algorithm used by an OpenPGP signature.
    """
    MD5: Final[HashAlgorithm]
    """
    MD5
    """
    RipeMD: Final[HashAlgorithm]
    """
    RIPEMD-160
    """
    SHA1: Final[HashAlgorithm]
    """
    SHA-1
    """
    SHA224: Final[HashAlgorithm]
    """
    SHA-224
    """
    SHA256: Final[HashAlgorithm]
    """
    SHA-256
    """
    SHA384: Final[HashAlgorithm]
    """
    SHA-384
    """
    SHA3_256: Final[HashAlgorithm]
    """
    SHA3-256
    """
    SHA3_512: Final[HashAlgorithm]
    """
    SHA3-512
    """
    SHA512: Final[HashAlgorithm]
    """
    SHA-512
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class KeyFlags:
    """
    The key usage flags from an OpenPGP signature.

    Indicates what operations a key is authorized to perform.
    """
    def __repr__(self, /) -> str: ...
    @property
    def authentication(self, /) -> bool:
        """
        Whether the key may be used for authentication.
        """
    @property
    def certification(self, /) -> bool:
        """
        Whether the key may be used to certify other keys.
        """
    @property
    def signing(self, /) -> bool:
        """
        Whether the key may be used to sign data.
        """
    @property
    def storage_encryption(self, /) -> bool:
        """
        Whether the key may be used to encrypt storage.
        """
    @property
    def transport_encryption(self, /) -> bool:
        """
        Whether the key may be used to encrypt communications.
        """

@final
class Packet:
    """
    A single OpenPGP packet.

    Provides the packet tag and type-specific accessors for extracting
    data from different packet types (keys, signatures, user IDs, etc.).
    Accessors return `None` when called on the wrong packet type.
    """
    def __bytes__(self, /) -> bytes:
        """
        The full serialized packet bytes (tag, length header, and body).
        """
    def __repr__(self, /) -> str: ...
    @property
    def body(self, /) -> bytes:
        """
        The raw body bytes of this packet (without the tag and length header).
        """
    @property
    def exportable(self, /) -> bool |None:
        """
        Whether the signature is exportable.

        Returns `None` for non-Signature packets or if the subpacket is absent.
        Most signatures are exportable by default.
        """
    @property
    def fingerprint(self, /) -> str |None:
        """
        The fingerprint of a key packet, as a lowercase hex string.

        Returns `None` for non-key packets.
        """
    @property
    def hash_algorithm(self, /) -> HashAlgorithm |None:
        """
        The hash algorithm used by a signature.

        Returns `None` for non-Signature packets.
        """
    @property
    def issuer_fingerprint(self, /) -> str |None:
        """
        The issuer fingerprint from a signature, as a lowercase hex string.

        Returns `None` for non-Signature packets or if not present.
        """
    @property
    def issuer_key_id(self, /) -> str |None:
        """
        The issuer key ID from a signature, as a lowercase hex string.

        Returns `None` for non-Signature packets or if not present.
        """
    @property
    def key_algorithm(self, /) -> PublicKeyAlgorithm |None:
        """
        The public key algorithm of a key packet.

        Returns `None` for non-key packets.
        """
    @property
    def key_created(self, /) -> datetime |None:
        """
        The creation time of a key packet.

        Returns `None` for non-key packets.
        """
    @property
    def key_flags(self, /) -> KeyFlags |None:
        """
        The key usage flags from a signature.

        Indicates what operations the key is authorized to perform
        (certification, signing, encryption, authentication).
        Returns `None` for non-Signature packets or if not present.
        """
    @property
    def key_id(self, /) -> str |None:
        """
        The short key ID of a key packet, as a lowercase hex string.

        Returns `None` for non-key packets.
        """
    @property
    def key_validity_period(self, /) -> timedelta |None:
        """
        The key validity period as a timedelta from key creation.

        Returns `None` for non-Signature packets or if not present.
        """
    @property
    def literal_data(self, /) -> bytes |None:
        """
        The payload content of a Literal Data packet (without format/filename/date header).

        Returns `None` for non-Literal Data packets.
        """
    @property
    def literal_date(self, /) -> datetime |None:
        """
        The date embedded in a Literal Data packet.

        Returns `None` for non-Literal Data packets or if no date is set.
        """
    @property
    def literal_filename(self, /) -> str |None:
        """
        The filename hint from a Literal Data packet.

        Returns `None` for non-Literal Data packets or if no filename is set.
        """
    @property
    def literal_format(self, /) -> DataFormat |None:
        """
        The data format of a Literal Data packet (Binary, Unicode, or Text).

        Returns `None` for non-Literal Data packets.
        """
    @property
    def notations(self, /) -> list[Notation] |None:
        """
        The notation data from a signature, as a list of `Notation` objects.

        Returns `None` for non-Signature packets.
        """
    @property
    def ops_issuer(self, /) -> str |None:
        """
        The issuer key ID from a One-Pass Signature packet, as a lowercase hex string.

        Returns `None` for non-One-Pass Signature packets.
        """
    @property
    def ops_signature_type(self, /) -> SignatureType |None:
        """
        The signature type from a One-Pass Signature packet.

        Returns `None` for non-One-Pass Signature packets.
        """
    @property
    def primary_userid(self, /) -> bool |None:
        """
        Whether the signature marks its User ID as the primary one.

        Returns `None` for non-Signature packets or if the subpacket is absent.
        """
    @property
    def signature_created(self, /) -> datetime |None:
        """
        The signature creation time.

        Returns `None` for non-Signature packets or if absent.
        """
    @property
    def signature_expiration_time(self, /) -> datetime |None:
        """
        The signature expiration time.

        Returns `None` for non-Signature packets or if the signature does not expire.
        """
    @property
    def signature_type(self, /) -> SignatureType |None:
        """
        The signature type (e.g. `SignatureType.SubkeyBinding`).

        Returns `None` for non-Signature packets.
        """
    @property
    def signature_validity_period(self, /) -> timedelta |None:
        """
        The signature validity period as a timedelta from creation time.

        Returns `None` for non-Signature packets or if the signature does not expire.
        """
    @property
    def signature_version(self, /) -> int |None:
        """
        The version of a signature packet (e.g. 4 or 6).

        Returns `None` for non-Signature packets.
        """
    @property
    def signers_user_id(self, /) -> str |None:
        """
        The signer's User ID from a signature.

        Returns `None` for non-Signature packets or if not present.
        """
    @property
    def tag(self, /) -> Tag:
        """
        The packet tag identifying the type of this packet (e.g. `Tag.Signature`).
        """
    @property
    def user_id(self, /) -> str |None:
        """
        The User ID string.

        Returns `None` for non-User ID packets.
        """
    @property
    def user_id_comment(self, /) -> str |None:
        """
        The comment component of a User ID.

        For example, from `"Alice (work) <alice@example.com>"` this returns `"work"`.
        Returns `None` for non-User ID packets, or if parsing fails or no comment is present.
        """
    @property
    def user_id_email(self, /) -> str |None:
        """
        The email component of a User ID.

        For example, from `"Alice <alice@example.com>"` this returns `"alice@example.com"`.
        Returns `None` for non-User ID packets, or if parsing fails or no email is present.
        """
    @property
    def user_id_name(self, /) -> str |None:
        """
        The name component of a User ID.

        For example, from `"Alice <alice@example.com>"` this returns `"Alice"`.
        Returns `None` for non-User ID packets, or if parsing fails or no name is present.
        """

@final
class PacketPile:
    """
    A parsed collection of OpenPGP packets.

    Wraps Sequoia's `PacketPile` to provide iteration over the individual
    packets contained in an OpenPGP message, key block, or signature.
    """
    def __iter__(self, /) -> Any: ...
    def __len__(self, /) -> int: ...
    def __repr__(self, /) -> str: ...
    @staticmethod
    def from_bytes(bytes: bytes) -> PacketPile:
        """
        Parse packets from a byte string.

        The input may be binary or ASCII-armored.
        """
    @staticmethod
    def from_file(path: str) -> PacketPile:
        """
        Parse packets from a file on disk.

        The file may be binary or ASCII-armored.
        """

@final
class PublicKeyAlgorithm:
    """
    The public key algorithm used by an OpenPGP key.
    """
    DSA: Final[PublicKeyAlgorithm]
    """
    DSA
    """
    ECDH: Final[PublicKeyAlgorithm]
    """
    Elliptic Curve Diffie-Hellman
    """
    ECDSA: Final[PublicKeyAlgorithm]
    """
    Elliptic Curve DSA
    """
    Ed25519: Final[PublicKeyAlgorithm]
    """
    Ed25519
    """
    Ed448: Final[PublicKeyAlgorithm]
    """
    Ed448
    """
    EdDSA: Final[PublicKeyAlgorithm]
    """
    "Twisted" Edwards Curve DSA
    """
    ElGamalEncrypt: Final[PublicKeyAlgorithm]
    """
    ElGamal Encrypt-Only, deprecated
    """
    ElGamalEncryptSign: Final[PublicKeyAlgorithm]
    """
    ElGamal Encrypt or Sign, deprecated
    """
    MLDSA65_Ed25519: Final[PublicKeyAlgorithm]
    """
    Composite ML-DSA-65 + Ed25519 signing algorithm
    """
    MLDSA87_Ed448: Final[PublicKeyAlgorithm]
    """
    Composite ML-DSA-87 + Ed448 signing algorithm
    """
    MLKEM1024_X448: Final[PublicKeyAlgorithm]
    """
    Composite ML-KEM-1024 + X448 encryption algorithm
    """
    MLKEM768_X25519: Final[PublicKeyAlgorithm]
    """
    Composite ML-KEM-768 + X25519 encryption algorithm
    """
    RSAEncrypt: Final[PublicKeyAlgorithm]
    """
    RSA Encrypt-Only, deprecated
    """
    RSAEncryptSign: Final[PublicKeyAlgorithm]
    """
    RSA (Encrypt or Sign)
    """
    RSASign: Final[PublicKeyAlgorithm]
    """
    RSA Sign-Only, deprecated
    """
    SLHDSA128f: Final[PublicKeyAlgorithm]
    """
    SLH-DSA 128-bit fast signatures
    """
    SLHDSA128s: Final[PublicKeyAlgorithm]
    """
    SLH-DSA 128-bit small signatures
    """
    SLHDSA256s: Final[PublicKeyAlgorithm]
    """
    SLH-DSA 256-bit small signatures
    """
    X25519: Final[PublicKeyAlgorithm]
    """
    X25519
    """
    X448: Final[PublicKeyAlgorithm]
    """
    X448
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class SignatureType:
    """
    The type of an OpenPGP signature, as defined in RFC 4880 / 9580.
    """
    Binary: Final[SignatureType]
    """
    Signature over a binary document
    """
    CasualCertification: Final[SignatureType]
    """
    Casual certification of a User ID and Public-Key packet
    """
    CertificationApproval: Final[SignatureType]
    """
    Certification Approval Key Signature (experimental)
    """
    CertificationRevocation: Final[SignatureType]
    """
    Certification revocation signature
    """
    Confirmation: Final[SignatureType]
    """
    Third-Party Confirmation signature
    """
    DirectKey: Final[SignatureType]
    """
    Signature directly on a key
    """
    GenericCertification: Final[SignatureType]
    """
    Generic certification of a User ID and Public-Key packet
    """
    KeyRevocation: Final[SignatureType]
    """
    Key revocation signature
    """
    PersonaCertification: Final[SignatureType]
    """
    Persona certification of a User ID and Public-Key packet
    """
    PositiveCertification: Final[SignatureType]
    """
    Positive certification of a User ID and Public-Key packet
    """
    PrimaryKeyBinding: Final[SignatureType]
    """
    Primary Key Binding Signature
    """
    Standalone: Final[SignatureType]
    """
    Standalone signature
    """
    SubkeyBinding: Final[SignatureType]
    """
    Subkey Binding Signature
    """
    SubkeyRevocation: Final[SignatureType]
    """
    Subkey revocation signature
    """
    Text: Final[SignatureType]
    """
    Signature over a canonical text document
    """
    Timestamp: Final[SignatureType]
    """
    Timestamp signature
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...

@final
class Tag:
    """
    The OpenPGP packet tag, identifying the type of a packet.
    """
    AED: Final[Tag]
    """
    AEAD Encrypted Data Packet
    """
    CompressedData: Final[Tag]
    """
    Compressed Data Packet
    """
    Literal: Final[Tag]
    """
    Literal Data Packet
    """
    MDC: Final[Tag]
    """
    Modification Detection Code Packet
    """
    Marker: Final[Tag]
    """
    Marker Packet
    """
    OnePassSig: Final[Tag]
    """
    One-Pass Signature Packet
    """
    PKESK: Final[Tag]
    """
    Public-Key Encrypted Session Key Packet
    """
    Padding: Final[Tag]
    """
    Padding Packet
    """
    PublicKey: Final[Tag]
    """
    Public-Key Packet
    """
    PublicSubkey: Final[Tag]
    """
    Public-Subkey Packet
    """
    Reserved: Final[Tag]
    """
    Reserved
    """
    SED: Final[Tag]
    """
    Symmetrically Encrypted Data Packet
    """
    SEIP: Final[Tag]
    """
    Symmetrically Encrypted and Integrity Protected Data Packet
    """
    SKESK: Final[Tag]
    """
    Symmetric-Key Encrypted Session Key Packet
    """
    SecretKey: Final[Tag]
    """
    Secret-Key Packet
    """
    SecretSubkey: Final[Tag]
    """
    Secret-Subkey Packet
    """
    Signature: Final[Tag]
    """
    Signature Packet
    """
    Trust: Final[Tag]
    """
    Trust Packet
    """
    UserAttribute: Final[Tag]
    """
    User Attribute Packet
    """
    UserID: Final[Tag]
    """
    User ID Packet
    """
    def __eq__(self, value: object, /) -> bool: ...
    def __int__(self, /) -> int: ...
    def __ne__(self, value: object, /) -> bool: ...
    def __repr__(self, /) -> str: ...
